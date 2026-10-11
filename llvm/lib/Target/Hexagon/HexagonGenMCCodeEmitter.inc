/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Machine Code Emitter                                                       *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

uint64_t HexagonMCCodeEmitter::getBinaryCodeForInstr(const MCInst &MI,
    SmallVectorImpl<MCFixup> &Fixups,
    const MCSubtargetInfo &STI) const {
  static const uint64_t InstBits[] = {
    UINT64_C(2357198976),	// A2_abs
    UINT64_C(2155872448),	// A2_absp
    UINT64_C(2357199008),	// A2_abssat
    UINT64_C(4076863488),	// A2_add
    UINT64_C(3577741408),	// A2_addh_h16_hh
    UINT64_C(3577741376),	// A2_addh_h16_hl
    UINT64_C(3577741344),	// A2_addh_h16_lh
    UINT64_C(3577741312),	// A2_addh_h16_ll
    UINT64_C(3577741536),	// A2_addh_h16_sat_hh
    UINT64_C(3577741504),	// A2_addh_h16_sat_hl
    UINT64_C(3577741472),	// A2_addh_h16_sat_lh
    UINT64_C(3577741440),	// A2_addh_h16_sat_ll
    UINT64_C(3573547072),	// A2_addh_l16_hl
    UINT64_C(3573547008),	// A2_addh_l16_ll
    UINT64_C(3573547200),	// A2_addh_l16_sat_hl
    UINT64_C(3573547136),	// A2_addh_l16_sat_ll
    UINT64_C(2952790016),	// A2_addi
    UINT64_C(3539992800),	// A2_addp
    UINT64_C(3546284192),	// A2_addpsat
    UINT64_C(4131389440),	// A2_addsat
    UINT64_C(3546284256),	// A2_addsph
    UINT64_C(3546284224),	// A2_addspl
    UINT64_C(4043309056),	// A2_and
    UINT64_C(1979711488),	// A2_andir
    UINT64_C(3554672640),	// A2_andp
    UINT64_C(1879048192),	// A2_aslh
    UINT64_C(1881145344),	// A2_asrh
    UINT64_C(4085252096),	// A2_combine_hh
    UINT64_C(4087349248),	// A2_combine_hl
    UINT64_C(4089446400),	// A2_combine_lh
    UINT64_C(4091543552),	// A2_combine_ll
    UINT64_C(2080374784),	// A2_combineii
    UINT64_C(4110417920),	// A2_combinew
    UINT64_C(3586129920),	// A2_max
    UINT64_C(3552575616),	// A2_maxp
    UINT64_C(3586130048),	// A2_maxu
    UINT64_C(3552575648),	// A2_maxup
    UINT64_C(3584032768),	// A2_min
    UINT64_C(3550478528),	// A2_minp
    UINT64_C(3584032896),	// A2_minu
    UINT64_C(3550478560),	// A2_minup
    UINT64_C(2155872416),	// A2_negp
    UINT64_C(2357199040),	// A2_negsat
    UINT64_C(2130706432),	// A2_nop
    UINT64_C(2155872384),	// A2_notp
    UINT64_C(4045406208),	// A2_or
    UINT64_C(1988100096),	// A2_orir
    UINT64_C(3554672704),	// A2_orp
    UINT64_C(4211081344),	// A2_paddf
    UINT64_C(4211089536),	// A2_paddfnew
    UINT64_C(1954545664),	// A2_paddif
    UINT64_C(1954553856),	// A2_paddifnew
    UINT64_C(1946157056),	// A2_paddit
    UINT64_C(1946165248),	// A2_padditnew
    UINT64_C(4211081216),	// A2_paddt
    UINT64_C(4211089408),	// A2_paddtnew
    UINT64_C(4177526912),	// A2_pandf
    UINT64_C(4177535104),	// A2_pandfnew
    UINT64_C(4177526784),	// A2_pandt
    UINT64_C(4177534976),	// A2_pandtnew
    UINT64_C(4179624064),	// A2_porf
    UINT64_C(4179632256),	// A2_porfnew
    UINT64_C(4179623936),	// A2_port
    UINT64_C(4179632128),	// A2_portnew
    UINT64_C(4213178496),	// A2_psubf
    UINT64_C(4213186688),	// A2_psubfnew
    UINT64_C(4213178368),	// A2_psubt
    UINT64_C(4213186560),	// A2_psubtnew
    UINT64_C(4183818368),	// A2_pxorf
    UINT64_C(4183826560),	// A2_pxorfnew
    UINT64_C(4183818240),	// A2_pxort
    UINT64_C(4183826432),	// A2_pxortnew
    UINT64_C(2294284320),	// A2_roundsat
    UINT64_C(2294284288),	// A2_sat
    UINT64_C(2361393376),	// A2_satb
    UINT64_C(2361393280),	// A2_sath
    UINT64_C(2361393344),	// A2_satub
    UINT64_C(2361393312),	// A2_satuh
    UINT64_C(4078960640),	// A2_sub
    UINT64_C(3579838560),	// A2_subh_h16_hh
    UINT64_C(3579838528),	// A2_subh_h16_hl
    UINT64_C(3579838496),	// A2_subh_h16_lh
    UINT64_C(3579838464),	// A2_subh_h16_ll
    UINT64_C(3579838688),	// A2_subh_h16_sat_hh
    UINT64_C(3579838656),	// A2_subh_h16_sat_hl
    UINT64_C(3579838624),	// A2_subh_h16_sat_lh
    UINT64_C(3579838592),	// A2_subh_h16_sat_ll
    UINT64_C(3575644224),	// A2_subh_l16_hl
    UINT64_C(3575644160),	// A2_subh_l16_ll
    UINT64_C(3575644352),	// A2_subh_l16_sat_hl
    UINT64_C(3575644288),	// A2_subh_l16_sat_ll
    UINT64_C(3542089952),	// A2_subp
    UINT64_C(1983905792),	// A2_subri
    UINT64_C(4139778048),	// A2_subsat
    UINT64_C(4127195136),	// A2_svaddh
    UINT64_C(4129292288),	// A2_svaddhs
    UINT64_C(4133486592),	// A2_svadduhs
    UINT64_C(4143972352),	// A2_svavgh
    UINT64_C(4146069504),	// A2_svavghs
    UINT64_C(4150263808),	// A2_svnavgh
    UINT64_C(4135583744),	// A2_svsubh
    UINT64_C(4137680896),	// A2_svsubhs
    UINT64_C(4141875200),	// A2_svsubuhs
    UINT64_C(2357199072),	// A2_swiz
    UINT64_C(1889533952),	// A2_sxtb
    UINT64_C(1893728256),	// A2_sxth
    UINT64_C(2218786816),	// A2_sxtw
    UINT64_C(1885339648),	// A2_tfr
    UINT64_C(1778384896),	// A2_tfrcrr
    UINT64_C(1914699776),	// A2_tfrih
    UINT64_C(1897922560),	// A2_tfril
    UINT64_C(1646264320),	// A2_tfrrcr
    UINT64_C(2013265920),	// A2_tfrsi
    UINT64_C(2151678080),	// A2_vabsh
    UINT64_C(2151678112),	// A2_vabshsat
    UINT64_C(2151678144),	// A2_vabsw
    UINT64_C(2151678176),	// A2_vabswsat
    UINT64_C(3539992640),	// A2_vaddh
    UINT64_C(3539992672),	// A2_vaddhs
    UINT64_C(3539992576),	// A2_vaddub
    UINT64_C(3539992608),	// A2_vaddubs
    UINT64_C(3539992704),	// A2_vadduhs
    UINT64_C(3539992736),	// A2_vaddw
    UINT64_C(3539992768),	// A2_vaddws
    UINT64_C(3544186944),	// A2_vavgh
    UINT64_C(3544187008),	// A2_vavghcr
    UINT64_C(3544186976),	// A2_vavghr
    UINT64_C(3544186880),	// A2_vavgub
    UINT64_C(3544186912),	// A2_vavgubr
    UINT64_C(3544187040),	// A2_vavguh
    UINT64_C(3544187072),	// A2_vavguhr
    UINT64_C(3546284128),	// A2_vavguw
    UINT64_C(3546284160),	// A2_vavguwr
    UINT64_C(3546284032),	// A2_vavgw
    UINT64_C(3546284096),	// A2_vavgwcr
    UINT64_C(3546284064),	// A2_vavgwr
    UINT64_C(3523215552),	// A2_vcmpbeq
    UINT64_C(3523215584),	// A2_vcmpbgtu
    UINT64_C(3523215456),	// A2_vcmpheq
    UINT64_C(3523215488),	// A2_vcmphgt
    UINT64_C(3523215520),	// A2_vcmphgtu
    UINT64_C(3523215360),	// A2_vcmpweq
    UINT64_C(3523215392),	// A2_vcmpwgt
    UINT64_C(3523215424),	// A2_vcmpwgtu
    UINT64_C(2155872480),	// A2_vconj
    UINT64_C(3552575680),	// A2_vmaxb
    UINT64_C(3552575520),	// A2_vmaxh
    UINT64_C(3552575488),	// A2_vmaxub
    UINT64_C(3552575552),	// A2_vmaxuh
    UINT64_C(3550478496),	// A2_vmaxuw
    UINT64_C(3552575584),	// A2_vmaxw
    UINT64_C(3552575712),	// A2_vminb
    UINT64_C(3550478368),	// A2_vminh
    UINT64_C(3550478336),	// A2_vminub
    UINT64_C(3550478400),	// A2_vminuh
    UINT64_C(3550478464),	// A2_vminuw
    UINT64_C(3550478432),	// A2_vminw
    UINT64_C(3548381184),	// A2_vnavgh
    UINT64_C(3548381248),	// A2_vnavghcr
    UINT64_C(3548381216),	// A2_vnavghr
    UINT64_C(3548381280),	// A2_vnavgw
    UINT64_C(3548381376),	// A2_vnavgwcr
    UINT64_C(3548381312),	// A2_vnavgwr
    UINT64_C(3896508448),	// A2_vraddub
    UINT64_C(3930062880),	// A2_vraddub_acc
    UINT64_C(3896508480),	// A2_vrsadub
    UINT64_C(3930062912),	// A2_vrsadub_acc
    UINT64_C(3542089792),	// A2_vsubh
    UINT64_C(3542089824),	// A2_vsubhs
    UINT64_C(3542089728),	// A2_vsubub
    UINT64_C(3542089760),	// A2_vsububs
    UINT64_C(3542089856),	// A2_vsubuhs
    UINT64_C(3542089888),	// A2_vsubw
    UINT64_C(3542089920),	// A2_vsubws
    UINT64_C(4049600512),	// A2_xor
    UINT64_C(3554672768),	// A2_xorp
    UINT64_C(1891631104),	// A2_zxth
    UINT64_C(3267362816),	// A4_addp_c
    UINT64_C(4051697664),	// A4_andn
    UINT64_C(3554672672),	// A4_andnp
    UINT64_C(3558866944),	// A4_bitsplit
    UINT64_C(2294284416),	// A4_bitspliti
    UINT64_C(3523223712),	// A4_boundscheck_hi
    UINT64_C(3523223680),	// A4_boundscheck_lo
    UINT64_C(3351249088),	// A4_cmpbeq
    UINT64_C(3707764736),	// A4_cmpbeqi
    UINT64_C(3351248960),	// A4_cmpbgt
    UINT64_C(3709861888),	// A4_cmpbgti
    UINT64_C(3351249120),	// A4_cmpbgtu
    UINT64_C(3711959040),	// A4_cmpbgtui
    UINT64_C(3351248992),	// A4_cmpheq
    UINT64_C(3707764744),	// A4_cmpheqi
    UINT64_C(3351249024),	// A4_cmphgt
    UINT64_C(3709861896),	// A4_cmphgti
    UINT64_C(3351249056),	// A4_cmphgtu
    UINT64_C(3711959048),	// A4_cmphgtui
    UINT64_C(2088763392),	// A4_combineii
    UINT64_C(1931485184),	// A4_combineir
    UINT64_C(1929388032),	// A4_combineri
    UINT64_C(2363490304),	// A4_cround_ri
    UINT64_C(3334471680),	// A4_cround_rr
    UINT64_C(0),	// A4_ext
    UINT64_C(3554672864),	// A4_modwrapu
    UINT64_C(4053794816),	// A4_orn
    UINT64_C(3554672736),	// A4_ornp
    UINT64_C(1879058432),	// A4_paslhf
    UINT64_C(1879059456),	// A4_paslhfnew
    UINT64_C(1879056384),	// A4_paslht
    UINT64_C(1879057408),	// A4_paslhtnew
    UINT64_C(1881155584),	// A4_pasrhf
    UINT64_C(1881156608),	// A4_pasrhfnew
    UINT64_C(1881153536),	// A4_pasrht
    UINT64_C(1881154560),	// A4_pasrhtnew
    UINT64_C(1889544192),	// A4_psxtbf
    UINT64_C(1889545216),	// A4_psxtbfnew
    UINT64_C(1889542144),	// A4_psxtbt
    UINT64_C(1889543168),	// A4_psxtbtnew
    UINT64_C(1893738496),	// A4_psxthf
    UINT64_C(1893739520),	// A4_psxthfnew
    UINT64_C(1893736448),	// A4_psxtht
    UINT64_C(1893737472),	// A4_psxthtnew
    UINT64_C(1887447040),	// A4_pzxtbf
    UINT64_C(1887448064),	// A4_pzxtbfnew
    UINT64_C(1887444992),	// A4_pzxtbt
    UINT64_C(1887446016),	// A4_pzxtbtnew
    UINT64_C(1891641344),	// A4_pzxthf
    UINT64_C(1891642368),	// A4_pzxthfnew
    UINT64_C(1891639296),	// A4_pzxtht
    UINT64_C(1891640320),	// A4_pzxthtnew
    UINT64_C(4081057792),	// A4_rcmpeq
    UINT64_C(1933582336),	// A4_rcmpeqi
    UINT64_C(4083154944),	// A4_rcmpneq
    UINT64_C(1935679488),	// A4_rcmpneqi
    UINT64_C(2363490432),	// A4_round_ri
    UINT64_C(2363490496),	// A4_round_ri_sat
    UINT64_C(3334471808),	// A4_round_rr
    UINT64_C(3334471872),	// A4_round_rr_sat
    UINT64_C(3269459968),	// A4_subp_c
    UINT64_C(1744830464),	// A4_tfrcpp
    UINT64_C(1663041536),	// A4_tfrpcp
    UINT64_C(3523223648),	// A4_tlbmatch
    UINT64_C(3523223552),	// A4_vcmpbeq_any
    UINT64_C(3690987520),	// A4_vcmpbeqi
    UINT64_C(3523223616),	// A4_vcmpbgt
    UINT64_C(3693084672),	// A4_vcmpbgti
    UINT64_C(3695181824),	// A4_vcmpbgtui
    UINT64_C(3690987528),	// A4_vcmpheqi
    UINT64_C(3693084680),	// A4_vcmphgti
    UINT64_C(3695181832),	// A4_vcmphgtui
    UINT64_C(3690987536),	// A4_vcmpweqi
    UINT64_C(3693084688),	// A4_vcmpwgti
    UINT64_C(3695181840),	// A4_vcmpwgtui
    UINT64_C(3407872032),	// A4_vrmaxh
    UINT64_C(3407880224),	// A4_vrmaxuh
    UINT64_C(3407880256),	// A4_vrmaxuw
    UINT64_C(3407872064),	// A4_vrmaxw
    UINT64_C(3407872160),	// A4_vrminh
    UINT64_C(3407880352),	// A4_vrminuh
    UINT64_C(3407880384),	// A4_vrminuw
    UINT64_C(3407872192),	// A4_vrminw
    UINT64_C(3936354304),	// A5_ACS
    UINT64_C(3242197024),	// A5_vaddhubs
    UINT64_C(3523223584),	// A6_vcmpbeq_notany
    UINT64_C(3940548608),	// A6_vminub_RdP
    UINT64_C(2294284448),	// A7_clip
    UINT64_C(2363490368),	// A7_croundd_ri
    UINT64_C(3334471744),	// A7_croundd_rr
    UINT64_C(2294284480),	// A7_vclip
    UINT64_C(1805647872),	// C2_all8
    UINT64_C(1795162112),	// C2_and
    UINT64_C(1801453568),	// C2_andn
    UINT64_C(1803550720),	// C2_any8
    UINT64_C(3347054592),	// C2_bitsclr
    UINT64_C(2239758336),	// C2_bitsclri
    UINT64_C(3342860288),	// C2_bitsset
    UINT64_C(4244635776),	// C2_ccombinewf
    UINT64_C(4244643968),	// C2_ccombinewnewf
    UINT64_C(4244643840),	// C2_ccombinewnewt
    UINT64_C(4244635648),	// C2_ccombinewt
    UINT64_C(2122317824),	// C2_cmoveif
    UINT64_C(2113929216),	// C2_cmoveit
    UINT64_C(2122326016),	// C2_cmovenewif
    UINT64_C(2113937408),	// C2_cmovenewit
    UINT64_C(4060086272),	// C2_cmpeq
    UINT64_C(1962934272),	// C2_cmpeqi
    UINT64_C(3531603968),	// C2_cmpeqp
    UINT64_C(4064280576),	// C2_cmpgt
    UINT64_C(1967128576),	// C2_cmpgti
    UINT64_C(3531604032),	// C2_cmpgtp
    UINT64_C(4066377728),	// C2_cmpgtu
    UINT64_C(1971322880),	// C2_cmpgtui
    UINT64_C(3531604096),	// C2_cmpgtup
    UINT64_C(2248146944),	// C2_mask
    UINT64_C(4093640704),	// C2_mux
    UINT64_C(2046820352),	// C2_muxii
    UINT64_C(1929379840),	// C2_muxir
    UINT64_C(1937768448),	// C2_muxri
    UINT64_C(1807745024),	// C2_not
    UINT64_C(1797259264),	// C2_or
    UINT64_C(1809842176),	// C2_orn
    UINT64_C(2302672896),	// C2_tfrpr
    UINT64_C(2235564032),	// C2_tfrrp
    UINT64_C(2298478592),	// C2_vitpack
    UINT64_C(3506438144),	// C2_vmux
    UINT64_C(1799356416),	// C2_xor
    UINT64_C(1783169024),	// C4_addipc
    UINT64_C(1796210688),	// C4_and_and
    UINT64_C(1804599296),	// C4_and_andn
    UINT64_C(1798307840),	// C4_and_or
    UINT64_C(1806696448),	// C4_and_orn
    UINT64_C(4064280592),	// C4_cmplte
    UINT64_C(1967128592),	// C4_cmpltei
    UINT64_C(4066377744),	// C4_cmplteu
    UINT64_C(1971322896),	// C4_cmplteui
    UINT64_C(4060086288),	// C4_cmpneq
    UINT64_C(1962934288),	// C4_cmpneqi
    UINT64_C(1795170448),	// C4_fastcorner9
    UINT64_C(1796219024),	// C4_fastcorner9_not
    UINT64_C(3349151744),	// C4_nbitsclr
    UINT64_C(2241855488),	// C4_nbitsclri
    UINT64_C(3344957440),	// C4_nbitsset
    UINT64_C(1800404992),	// C4_or_and
    UINT64_C(1808793600),	// C4_or_andn
    UINT64_C(1802502144),	// C4_or_or
    UINT64_C(1810890752),	// C4_or_orn
    UINT64_C(1509949440),	// CALLProfile
    UINT64_C(0),	// CONST32
    UINT64_C(0),	// CONST64
    UINT64_C(0),	// DuplexIClass0
    UINT64_C(8192),	// DuplexIClass1
    UINT64_C(536870912),	// DuplexIClass2
    UINT64_C(536879104),	// DuplexIClass3
    UINT64_C(1073741824),	// DuplexIClass4
    UINT64_C(1073750016),	// DuplexIClass5
    UINT64_C(1610612736),	// DuplexIClass6
    UINT64_C(1610620928),	// DuplexIClass7
    UINT64_C(2147483648),	// DuplexIClass8
    UINT64_C(2147491840),	// DuplexIClass9
    UINT64_C(2684354560),	// DuplexIClassA
    UINT64_C(2684362752),	// DuplexIClassB
    UINT64_C(3221225472),	// DuplexIClassC
    UINT64_C(3221233664),	// DuplexIClassD
    UINT64_C(3758096384),	// DuplexIClassE
    UINT64_C(3758104576),	// DuplexIClassF
    UINT64_C(1384120320),	// EH_RETURN_JMPR
    UINT64_C(2162163808),	// F2_conv_d2df
    UINT64_C(2285895712),	// F2_conv_d2sf
    UINT64_C(2162163712),	// F2_conv_df2d
    UINT64_C(2162163904),	// F2_conv_df2d_chop
    UINT64_C(2281701408),	// F2_conv_df2sf
    UINT64_C(2162163744),	// F2_conv_df2ud
    UINT64_C(2162163936),	// F2_conv_df2ud_chop
    UINT64_C(2287992864),	// F2_conv_df2uw
    UINT64_C(2292187168),	// F2_conv_df2uw_chop
    UINT64_C(2290090016),	// F2_conv_df2w
    UINT64_C(2296381472),	// F2_conv_df2w_chop
    UINT64_C(2222981248),	// F2_conv_sf2d
    UINT64_C(2222981312),	// F2_conv_sf2d_chop
    UINT64_C(2222981120),	// F2_conv_sf2df
    UINT64_C(2222981216),	// F2_conv_sf2ud
    UINT64_C(2222981280),	// F2_conv_sf2ud_chop
    UINT64_C(2338324480),	// F2_conv_sf2uw
    UINT64_C(2338324512),	// F2_conv_sf2uw_chop
    UINT64_C(2340421632),	// F2_conv_sf2w
    UINT64_C(2340421664),	// F2_conv_sf2w_chop
    UINT64_C(2162163776),	// F2_conv_ud2df
    UINT64_C(2283798560),	// F2_conv_ud2sf
    UINT64_C(2222981152),	// F2_conv_uw2df
    UINT64_C(2334130176),	// F2_conv_uw2sf
    UINT64_C(2222981184),	// F2_conv_w2df
    UINT64_C(2336227328),	// F2_conv_w2sf
    UINT64_C(3892314208),	// F2_dfadd
    UINT64_C(3699376144),	// F2_dfclass
    UINT64_C(3537895424),	// F2_dfcmpeq
    UINT64_C(3537895488),	// F2_dfcmpge
    UINT64_C(3537895456),	// F2_dfcmpgt
    UINT64_C(3537895520),	// F2_dfcmpuo
    UINT64_C(3644850176),	// F2_dfimm_n
    UINT64_C(3640655872),	// F2_dfimm_p
    UINT64_C(3894411360),	// F2_dfmax
    UINT64_C(3904897120),	// F2_dfmin
    UINT64_C(3896508512),	// F2_dfmpyfix
    UINT64_C(3934257248),	// F2_dfmpyhh
    UINT64_C(3925868640),	// F2_dfmpylh
    UINT64_C(3902799968),	// F2_dfmpyll
    UINT64_C(3900702816),	// F2_dfsub
    UINT64_C(3942645760),	// F2_sfadd
    UINT64_C(2246049792),	// F2_sfclass
    UINT64_C(3353346144),	// F2_sfcmpeq
    UINT64_C(3353346048),	// F2_sfcmpge
    UINT64_C(3353346176),	// F2_sfcmpgt
    UINT64_C(3353346080),	// F2_sfcmpuo
    UINT64_C(3955228704),	// F2_sffixupd
    UINT64_C(3955228672),	// F2_sffixupn
    UINT64_C(2342518784),	// F2_sffixupr
    UINT64_C(4009754752),	// F2_sffma
    UINT64_C(4009754816),	// F2_sffma_lib
    UINT64_C(4016046208),	// F2_sffma_sc
    UINT64_C(4009754784),	// F2_sffms
    UINT64_C(4009754848),	// F2_sffms_lib
    UINT64_C(3594518528),	// F2_sfimm_n
    UINT64_C(3590324224),	// F2_sfimm_p
    UINT64_C(2346713088),	// F2_sfinvsqrta
    UINT64_C(3951034368),	// F2_sfmax
    UINT64_C(3951034400),	// F2_sfmin
    UINT64_C(3946840064),	// F2_sfmpy
    UINT64_C(3957325952),	// F2_sfrecipa
    UINT64_C(3942645792),	// F2_sfsub
    UINT64_C(1746927616),	// G4_tfrgcpp
    UINT64_C(1780482048),	// G4_tfrgcrr
    UINT64_C(1660944384),	// G4_tfrgpcp
    UINT64_C(1644167168),	// G4_tfrgrcr
    UINT64_C(35651584),	// HI
    UINT64_C(1509949440),	// J2_call
    UINT64_C(1562378240),	// J2_callf
    UINT64_C(1352663040),	// J2_callr
    UINT64_C(1361051648),	// J2_callrf
    UINT64_C(1354760192),	// J2_callrh
    UINT64_C(1358954496),	// J2_callrt
    UINT64_C(1560281088),	// J2_callt
    UINT64_C(1476395008),	// J2_jump
    UINT64_C(1545601024),	// J2_jumpf
    UINT64_C(1545603072),	// J2_jumpfnew
    UINT64_C(1545607168),	// J2_jumpfnewpt
    UINT64_C(1545605120),	// J2_jumpfpt
    UINT64_C(1384120320),	// J2_jumpr
    UINT64_C(1398800384),	// J2_jumprf
    UINT64_C(1398802432),	// J2_jumprfnew
    UINT64_C(1398806528),	// J2_jumprfnewpt
    UINT64_C(1398804480),	// J2_jumprfpt
    UINT64_C(1631584256),	// J2_jumprgtez
    UINT64_C(1631588352),	// J2_jumprgtezpt
    UINT64_C(1388314624),	// J2_jumprh
    UINT64_C(1639972864),	// J2_jumprltez
    UINT64_C(1639976960),	// J2_jumprltezpt
    UINT64_C(1635778560),	// J2_jumprnz
    UINT64_C(1635782656),	// J2_jumprnzpt
    UINT64_C(1396703232),	// J2_jumprt
    UINT64_C(1396705280),	// J2_jumprtnew
    UINT64_C(1396709376),	// J2_jumprtnewpt
    UINT64_C(1396707328),	// J2_jumprtpt
    UINT64_C(1627389952),	// J2_jumprz
    UINT64_C(1627394048),	// J2_jumprzpt
    UINT64_C(1543503872),	// J2_jumpt
    UINT64_C(1543505920),	// J2_jumptnew
    UINT64_C(1543510016),	// J2_jumptnewpt
    UINT64_C(1543507968),	// J2_jumptpt
    UINT64_C(1761607680),	// J2_loop0i
    UINT64_C(1761607680),	// J2_loop0iext
    UINT64_C(1610612736),	// J2_loop0r
    UINT64_C(1610612736),	// J2_loop0rext
    UINT64_C(1763704832),	// J2_loop1i
    UINT64_C(1763704832),	// J2_loop1iext
    UINT64_C(1612709888),	// J2_loop1r
    UINT64_C(1612709888),	// J2_loop1rext
    UINT64_C(1413480448),	// J2_pause
    UINT64_C(1772093440),	// J2_ploop1si
    UINT64_C(1621098496),	// J2_ploop1sr
    UINT64_C(1774190592),	// J2_ploop2si
    UINT64_C(1623195648),	// J2_ploop2sr
    UINT64_C(1776287744),	// J2_ploop3si
    UINT64_C(1625292800),	// J2_ploop3sr
    UINT64_C(1474297856),	// J2_rte
    UINT64_C(1409286144),	// J2_trap0
    UINT64_C(1417674752),	// J2_trap1
    UINT64_C(1474301952),	// J2_unpause
    UINT64_C(541065216),	// J4_cmpeq_f_jumpnv_nt
    UINT64_C(541073408),	// J4_cmpeq_f_jumpnv_t
    UINT64_C(339738624),	// J4_cmpeq_fp0_jump_nt
    UINT64_C(339746816),	// J4_cmpeq_fp0_jump_t
    UINT64_C(339742720),	// J4_cmpeq_fp1_jump_nt
    UINT64_C(339750912),	// J4_cmpeq_fp1_jump_t
    UINT64_C(536870912),	// J4_cmpeq_t_jumpnv_nt
    UINT64_C(536879104),	// J4_cmpeq_t_jumpnv_t
    UINT64_C(335544320),	// J4_cmpeq_tp0_jump_nt
    UINT64_C(335552512),	// J4_cmpeq_tp0_jump_t
    UINT64_C(335548416),	// J4_cmpeq_tp1_jump_nt
    UINT64_C(335556608),	// J4_cmpeq_tp1_jump_t
    UINT64_C(608174080),	// J4_cmpeqi_f_jumpnv_nt
    UINT64_C(608182272),	// J4_cmpeqi_f_jumpnv_t
    UINT64_C(272629760),	// J4_cmpeqi_fp0_jump_nt
    UINT64_C(272637952),	// J4_cmpeqi_fp0_jump_t
    UINT64_C(306184192),	// J4_cmpeqi_fp1_jump_nt
    UINT64_C(306192384),	// J4_cmpeqi_fp1_jump_t
    UINT64_C(603979776),	// J4_cmpeqi_t_jumpnv_nt
    UINT64_C(603987968),	// J4_cmpeqi_t_jumpnv_t
    UINT64_C(268435456),	// J4_cmpeqi_tp0_jump_nt
    UINT64_C(268443648),	// J4_cmpeqi_tp0_jump_t
    UINT64_C(301989888),	// J4_cmpeqi_tp1_jump_nt
    UINT64_C(301998080),	// J4_cmpeqi_tp1_jump_t
    UINT64_C(641728512),	// J4_cmpeqn1_f_jumpnv_nt
    UINT64_C(641736704),	// J4_cmpeqn1_f_jumpnv_t
    UINT64_C(297795584),	// J4_cmpeqn1_fp0_jump_nt
    UINT64_C(297803776),	// J4_cmpeqn1_fp0_jump_t
    UINT64_C(331350016),	// J4_cmpeqn1_fp1_jump_nt
    UINT64_C(331358208),	// J4_cmpeqn1_fp1_jump_t
    UINT64_C(637534208),	// J4_cmpeqn1_t_jumpnv_nt
    UINT64_C(637542400),	// J4_cmpeqn1_t_jumpnv_t
    UINT64_C(293601280),	// J4_cmpeqn1_tp0_jump_nt
    UINT64_C(293609472),	// J4_cmpeqn1_tp0_jump_t
    UINT64_C(327155712),	// J4_cmpeqn1_tp1_jump_nt
    UINT64_C(327163904),	// J4_cmpeqn1_tp1_jump_t
    UINT64_C(549453824),	// J4_cmpgt_f_jumpnv_nt
    UINT64_C(549462016),	// J4_cmpgt_f_jumpnv_t
    UINT64_C(348127232),	// J4_cmpgt_fp0_jump_nt
    UINT64_C(348135424),	// J4_cmpgt_fp0_jump_t
    UINT64_C(348131328),	// J4_cmpgt_fp1_jump_nt
    UINT64_C(348139520),	// J4_cmpgt_fp1_jump_t
    UINT64_C(545259520),	// J4_cmpgt_t_jumpnv_nt
    UINT64_C(545267712),	// J4_cmpgt_t_jumpnv_t
    UINT64_C(343932928),	// J4_cmpgt_tp0_jump_nt
    UINT64_C(343941120),	// J4_cmpgt_tp0_jump_t
    UINT64_C(343937024),	// J4_cmpgt_tp1_jump_nt
    UINT64_C(343945216),	// J4_cmpgt_tp1_jump_t
    UINT64_C(616562688),	// J4_cmpgti_f_jumpnv_nt
    UINT64_C(616570880),	// J4_cmpgti_f_jumpnv_t
    UINT64_C(281018368),	// J4_cmpgti_fp0_jump_nt
    UINT64_C(281026560),	// J4_cmpgti_fp0_jump_t
    UINT64_C(314572800),	// J4_cmpgti_fp1_jump_nt
    UINT64_C(314580992),	// J4_cmpgti_fp1_jump_t
    UINT64_C(612368384),	// J4_cmpgti_t_jumpnv_nt
    UINT64_C(612376576),	// J4_cmpgti_t_jumpnv_t
    UINT64_C(276824064),	// J4_cmpgti_tp0_jump_nt
    UINT64_C(276832256),	// J4_cmpgti_tp0_jump_t
    UINT64_C(310378496),	// J4_cmpgti_tp1_jump_nt
    UINT64_C(310386688),	// J4_cmpgti_tp1_jump_t
    UINT64_C(650117120),	// J4_cmpgtn1_f_jumpnv_nt
    UINT64_C(650125312),	// J4_cmpgtn1_f_jumpnv_t
    UINT64_C(297795840),	// J4_cmpgtn1_fp0_jump_nt
    UINT64_C(297804032),	// J4_cmpgtn1_fp0_jump_t
    UINT64_C(331350272),	// J4_cmpgtn1_fp1_jump_nt
    UINT64_C(331358464),	// J4_cmpgtn1_fp1_jump_t
    UINT64_C(645922816),	// J4_cmpgtn1_t_jumpnv_nt
    UINT64_C(645931008),	// J4_cmpgtn1_t_jumpnv_t
    UINT64_C(293601536),	// J4_cmpgtn1_tp0_jump_nt
    UINT64_C(293609728),	// J4_cmpgtn1_tp0_jump_t
    UINT64_C(327155968),	// J4_cmpgtn1_tp1_jump_nt
    UINT64_C(327164160),	// J4_cmpgtn1_tp1_jump_t
    UINT64_C(557842432),	// J4_cmpgtu_f_jumpnv_nt
    UINT64_C(557850624),	// J4_cmpgtu_f_jumpnv_t
    UINT64_C(356515840),	// J4_cmpgtu_fp0_jump_nt
    UINT64_C(356524032),	// J4_cmpgtu_fp0_jump_t
    UINT64_C(356519936),	// J4_cmpgtu_fp1_jump_nt
    UINT64_C(356528128),	// J4_cmpgtu_fp1_jump_t
    UINT64_C(553648128),	// J4_cmpgtu_t_jumpnv_nt
    UINT64_C(553656320),	// J4_cmpgtu_t_jumpnv_t
    UINT64_C(352321536),	// J4_cmpgtu_tp0_jump_nt
    UINT64_C(352329728),	// J4_cmpgtu_tp0_jump_t
    UINT64_C(352325632),	// J4_cmpgtu_tp1_jump_nt
    UINT64_C(352333824),	// J4_cmpgtu_tp1_jump_t
    UINT64_C(624951296),	// J4_cmpgtui_f_jumpnv_nt
    UINT64_C(624959488),	// J4_cmpgtui_f_jumpnv_t
    UINT64_C(289406976),	// J4_cmpgtui_fp0_jump_nt
    UINT64_C(289415168),	// J4_cmpgtui_fp0_jump_t
    UINT64_C(322961408),	// J4_cmpgtui_fp1_jump_nt
    UINT64_C(322969600),	// J4_cmpgtui_fp1_jump_t
    UINT64_C(620756992),	// J4_cmpgtui_t_jumpnv_nt
    UINT64_C(620765184),	// J4_cmpgtui_t_jumpnv_t
    UINT64_C(285212672),	// J4_cmpgtui_tp0_jump_nt
    UINT64_C(285220864),	// J4_cmpgtui_tp0_jump_t
    UINT64_C(318767104),	// J4_cmpgtui_tp1_jump_nt
    UINT64_C(318775296),	// J4_cmpgtui_tp1_jump_t
    UINT64_C(566231040),	// J4_cmplt_f_jumpnv_nt
    UINT64_C(566239232),	// J4_cmplt_f_jumpnv_t
    UINT64_C(562036736),	// J4_cmplt_t_jumpnv_nt
    UINT64_C(562044928),	// J4_cmplt_t_jumpnv_t
    UINT64_C(574619648),	// J4_cmpltu_f_jumpnv_nt
    UINT64_C(574627840),	// J4_cmpltu_f_jumpnv_t
    UINT64_C(570425344),	// J4_cmpltu_t_jumpnv_nt
    UINT64_C(570433536),	// J4_cmpltu_t_jumpnv_t
    UINT64_C(1386217472),	// J4_hintjumpr
    UINT64_C(369098752),	// J4_jumpseti
    UINT64_C(385875968),	// J4_jumpsetr
    UINT64_C(633339904),	// J4_tstbit0_f_jumpnv_nt
    UINT64_C(633348096),	// J4_tstbit0_f_jumpnv_t
    UINT64_C(297796352),	// J4_tstbit0_fp0_jump_nt
    UINT64_C(297804544),	// J4_tstbit0_fp0_jump_t
    UINT64_C(331350784),	// J4_tstbit0_fp1_jump_nt
    UINT64_C(331358976),	// J4_tstbit0_fp1_jump_t
    UINT64_C(629145600),	// J4_tstbit0_t_jumpnv_nt
    UINT64_C(629153792),	// J4_tstbit0_t_jumpnv_t
    UINT64_C(293602048),	// J4_tstbit0_tp0_jump_nt
    UINT64_C(293610240),	// J4_tstbit0_tp0_jump_t
    UINT64_C(327156480),	// J4_tstbit0_tp1_jump_nt
    UINT64_C(327164672),	// J4_tstbit0_tp1_jump_t
    UINT64_C(2415919104),	// L2_deallocframe
    UINT64_C(2424307712),	// L2_loadalignb_io
    UINT64_C(2659188736),	// L2_loadalignb_pbr
    UINT64_C(2558525440),	// L2_loadalignb_pci
    UINT64_C(2558525952),	// L2_loadalignb_pcr
    UINT64_C(2592079872),	// L2_loadalignb_pi
    UINT64_C(2625634304),	// L2_loadalignb_pr
    UINT64_C(2420113408),	// L2_loadalignh_io
    UINT64_C(2654994432),	// L2_loadalignh_pbr
    UINT64_C(2554331136),	// L2_loadalignh_pci
    UINT64_C(2554331648),	// L2_loadalignh_pcr
    UINT64_C(2587885568),	// L2_loadalignh_pi
    UINT64_C(2621440000),	// L2_loadalignh_pr
    UINT64_C(2418016256),	// L2_loadbsw2_io
    UINT64_C(2652897280),	// L2_loadbsw2_pbr
    UINT64_C(2552233984),	// L2_loadbsw2_pci
    UINT64_C(2552234496),	// L2_loadbsw2_pcr
    UINT64_C(2585788416),	// L2_loadbsw2_pi
    UINT64_C(2619342848),	// L2_loadbsw2_pr
    UINT64_C(2430599168),	// L2_loadbsw4_io
    UINT64_C(2665480192),	// L2_loadbsw4_pbr
    UINT64_C(2564816896),	// L2_loadbsw4_pci
    UINT64_C(2564817408),	// L2_loadbsw4_pcr
    UINT64_C(2598371328),	// L2_loadbsw4_pi
    UINT64_C(2631925760),	// L2_loadbsw4_pr
    UINT64_C(2422210560),	// L2_loadbzw2_io
    UINT64_C(2657091584),	// L2_loadbzw2_pbr
    UINT64_C(2556428288),	// L2_loadbzw2_pci
    UINT64_C(2556428800),	// L2_loadbzw2_pcr
    UINT64_C(2589982720),	// L2_loadbzw2_pi
    UINT64_C(2623537152),	// L2_loadbzw2_pr
    UINT64_C(2426404864),	// L2_loadbzw4_io
    UINT64_C(2661285888),	// L2_loadbzw4_pbr
    UINT64_C(2560622592),	// L2_loadbzw4_pci
    UINT64_C(2560623104),	// L2_loadbzw4_pcr
    UINT64_C(2594177024),	// L2_loadbzw4_pi
    UINT64_C(2627731456),	// L2_loadbzw4_pr
    UINT64_C(2432696320),	// L2_loadrb_io
    UINT64_C(2667577344),	// L2_loadrb_pbr
    UINT64_C(2566914048),	// L2_loadrb_pci
    UINT64_C(2566914560),	// L2_loadrb_pcr
    UINT64_C(2600468480),	// L2_loadrb_pi
    UINT64_C(2634022912),	// L2_loadrb_pr
    UINT64_C(1224736768),	// L2_loadrbgp
    UINT64_C(2445279232),	// L2_loadrd_io
    UINT64_C(2680160256),	// L2_loadrd_pbr
    UINT64_C(2579496960),	// L2_loadrd_pci
    UINT64_C(2579497472),	// L2_loadrd_pcr
    UINT64_C(2613051392),	// L2_loadrd_pi
    UINT64_C(2646605824),	// L2_loadrd_pr
    UINT64_C(1237319680),	// L2_loadrdgp
    UINT64_C(2436890624),	// L2_loadrh_io
    UINT64_C(2671771648),	// L2_loadrh_pbr
    UINT64_C(2571108352),	// L2_loadrh_pci
    UINT64_C(2571108864),	// L2_loadrh_pcr
    UINT64_C(2604662784),	// L2_loadrh_pi
    UINT64_C(2638217216),	// L2_loadrh_pr
    UINT64_C(1228931072),	// L2_loadrhgp
    UINT64_C(2441084928),	// L2_loadri_io
    UINT64_C(2675965952),	// L2_loadri_pbr
    UINT64_C(2575302656),	// L2_loadri_pci
    UINT64_C(2575303168),	// L2_loadri_pcr
    UINT64_C(2608857088),	// L2_loadri_pi
    UINT64_C(2642411520),	// L2_loadri_pr
    UINT64_C(1233125376),	// L2_loadrigp
    UINT64_C(2434793472),	// L2_loadrub_io
    UINT64_C(2669674496),	// L2_loadrub_pbr
    UINT64_C(2569011200),	// L2_loadrub_pci
    UINT64_C(2569011712),	// L2_loadrub_pcr
    UINT64_C(2602565632),	// L2_loadrub_pi
    UINT64_C(2636120064),	// L2_loadrub_pr
    UINT64_C(1226833920),	// L2_loadrubgp
    UINT64_C(2438987776),	// L2_loadruh_io
    UINT64_C(2673868800),	// L2_loadruh_pbr
    UINT64_C(2573205504),	// L2_loadruh_pci
    UINT64_C(2573206016),	// L2_loadruh_pcr
    UINT64_C(2606759936),	// L2_loadruh_pi
    UINT64_C(2640314368),	// L2_loadruh_pr
    UINT64_C(1231028224),	// L2_loadruhgp
    UINT64_C(2449475584),	// L2_loadw_aq
    UINT64_C(2449473536),	// L2_loadw_locked
    UINT64_C(1157627904),	// L2_ploadrbf_io
    UINT64_C(2600478720),	// L2_ploadrbf_pi
    UINT64_C(1191182336),	// L2_ploadrbfnew_io
    UINT64_C(2600482816),	// L2_ploadrbfnew_pi
    UINT64_C(1090519040),	// L2_ploadrbt_io
    UINT64_C(2600476672),	// L2_ploadrbt_pi
    UINT64_C(1124073472),	// L2_ploadrbtnew_io
    UINT64_C(2600480768),	// L2_ploadrbtnew_pi
    UINT64_C(1170210816),	// L2_ploadrdf_io
    UINT64_C(2613061632),	// L2_ploadrdf_pi
    UINT64_C(1203765248),	// L2_ploadrdfnew_io
    UINT64_C(2613065728),	// L2_ploadrdfnew_pi
    UINT64_C(1103101952),	// L2_ploadrdt_io
    UINT64_C(2613059584),	// L2_ploadrdt_pi
    UINT64_C(1136656384),	// L2_ploadrdtnew_io
    UINT64_C(2613063680),	// L2_ploadrdtnew_pi
    UINT64_C(1161822208),	// L2_ploadrhf_io
    UINT64_C(2604673024),	// L2_ploadrhf_pi
    UINT64_C(1195376640),	// L2_ploadrhfnew_io
    UINT64_C(2604677120),	// L2_ploadrhfnew_pi
    UINT64_C(1094713344),	// L2_ploadrht_io
    UINT64_C(2604670976),	// L2_ploadrht_pi
    UINT64_C(1128267776),	// L2_ploadrhtnew_io
    UINT64_C(2604675072),	// L2_ploadrhtnew_pi
    UINT64_C(1166016512),	// L2_ploadrif_io
    UINT64_C(2608867328),	// L2_ploadrif_pi
    UINT64_C(1199570944),	// L2_ploadrifnew_io
    UINT64_C(2608871424),	// L2_ploadrifnew_pi
    UINT64_C(1098907648),	// L2_ploadrit_io
    UINT64_C(2608865280),	// L2_ploadrit_pi
    UINT64_C(1132462080),	// L2_ploadritnew_io
    UINT64_C(2608869376),	// L2_ploadritnew_pi
    UINT64_C(1159725056),	// L2_ploadrubf_io
    UINT64_C(2602575872),	// L2_ploadrubf_pi
    UINT64_C(1193279488),	// L2_ploadrubfnew_io
    UINT64_C(2602579968),	// L2_ploadrubfnew_pi
    UINT64_C(1092616192),	// L2_ploadrubt_io
    UINT64_C(2602573824),	// L2_ploadrubt_pi
    UINT64_C(1126170624),	// L2_ploadrubtnew_io
    UINT64_C(2602577920),	// L2_ploadrubtnew_pi
    UINT64_C(1163919360),	// L2_ploadruhf_io
    UINT64_C(2606770176),	// L2_ploadruhf_pi
    UINT64_C(1197473792),	// L2_ploadruhfnew_io
    UINT64_C(2606774272),	// L2_ploadruhfnew_pi
    UINT64_C(1096810496),	// L2_ploadruht_io
    UINT64_C(2606768128),	// L2_ploadruht_pi
    UINT64_C(1130364928),	// L2_ploadruhtnew_io
    UINT64_C(2606772224),	// L2_ploadruhtnew_pi
    UINT64_C(1040187392),	// L4_add_memopb_io
    UINT64_C(1042284544),	// L4_add_memoph_io
    UINT64_C(1044381696),	// L4_add_memopw_io
    UINT64_C(1040187456),	// L4_and_memopb_io
    UINT64_C(1042284608),	// L4_and_memoph_io
    UINT64_C(1044381760),	// L4_and_memopw_io
    UINT64_C(1056964608),	// L4_iadd_memopb_io
    UINT64_C(1059061760),	// L4_iadd_memoph_io
    UINT64_C(1061158912),	// L4_iadd_memopw_io
    UINT64_C(1056964672),	// L4_iand_memopb_io
    UINT64_C(1059061824),	// L4_iand_memoph_io
    UINT64_C(1061158976),	// L4_iand_memopw_io
    UINT64_C(1056964704),	// L4_ior_memopb_io
    UINT64_C(1059061856),	// L4_ior_memoph_io
    UINT64_C(1061159008),	// L4_ior_memopw_io
    UINT64_C(1056964640),	// L4_isub_memopb_io
    UINT64_C(1059061792),	// L4_isub_memoph_io
    UINT64_C(1061158944),	// L4_isub_memopw_io
    UINT64_C(2592083968),	// L4_loadalignb_ap
    UINT64_C(2625638400),	// L4_loadalignb_ur
    UINT64_C(2587889664),	// L4_loadalignh_ap
    UINT64_C(2621444096),	// L4_loadalignh_ur
    UINT64_C(2585792512),	// L4_loadbsw2_ap
    UINT64_C(2619346944),	// L4_loadbsw2_ur
    UINT64_C(2598375424),	// L4_loadbsw4_ap
    UINT64_C(2631929856),	// L4_loadbsw4_ur
    UINT64_C(2589986816),	// L4_loadbzw2_ap
    UINT64_C(2623541248),	// L4_loadbzw2_ur
    UINT64_C(2594181120),	// L4_loadbzw4_ap
    UINT64_C(2627735552),	// L4_loadbzw4_ur
    UINT64_C(2449479680),	// L4_loadd_aq
    UINT64_C(2449477632),	// L4_loadd_locked
    UINT64_C(2600472576),	// L4_loadrb_ap
    UINT64_C(973078528),	// L4_loadrb_rr
    UINT64_C(2634027008),	// L4_loadrb_ur
    UINT64_C(2613055488),	// L4_loadrd_ap
    UINT64_C(985661440),	// L4_loadrd_rr
    UINT64_C(2646609920),	// L4_loadrd_ur
    UINT64_C(2604666880),	// L4_loadrh_ap
    UINT64_C(977272832),	// L4_loadrh_rr
    UINT64_C(2638221312),	// L4_loadrh_ur
    UINT64_C(2608861184),	// L4_loadri_ap
    UINT64_C(981467136),	// L4_loadri_rr
    UINT64_C(2642415616),	// L4_loadri_ur
    UINT64_C(2602569728),	// L4_loadrub_ap
    UINT64_C(975175680),	// L4_loadrub_rr
    UINT64_C(2636124160),	// L4_loadrub_ur
    UINT64_C(2606764032),	// L4_loadruh_ap
    UINT64_C(979369984),	// L4_loadruh_rr
    UINT64_C(2640318464),	// L4_loadruh_ur
    UINT64_C(2449481728),	// L4_loadw_phys
    UINT64_C(1040187488),	// L4_or_memopb_io
    UINT64_C(1042284640),	// L4_or_memoph_io
    UINT64_C(1044381792),	// L4_or_memopw_io
    UINT64_C(2667587712),	// L4_ploadrbf_abs
    UINT64_C(822083584),	// L4_ploadrbf_rr
    UINT64_C(2667591808),	// L4_ploadrbfnew_abs
    UINT64_C(855638016),	// L4_ploadrbfnew_rr
    UINT64_C(2667585664),	// L4_ploadrbt_abs
    UINT64_C(805306368),	// L4_ploadrbt_rr
    UINT64_C(2667589760),	// L4_ploadrbtnew_abs
    UINT64_C(838860800),	// L4_ploadrbtnew_rr
    UINT64_C(2680170624),	// L4_ploadrdf_abs
    UINT64_C(834666496),	// L4_ploadrdf_rr
    UINT64_C(2680174720),	// L4_ploadrdfnew_abs
    UINT64_C(868220928),	// L4_ploadrdfnew_rr
    UINT64_C(2680168576),	// L4_ploadrdt_abs
    UINT64_C(817889280),	// L4_ploadrdt_rr
    UINT64_C(2680172672),	// L4_ploadrdtnew_abs
    UINT64_C(851443712),	// L4_ploadrdtnew_rr
    UINT64_C(2671782016),	// L4_ploadrhf_abs
    UINT64_C(826277888),	// L4_ploadrhf_rr
    UINT64_C(2671786112),	// L4_ploadrhfnew_abs
    UINT64_C(859832320),	// L4_ploadrhfnew_rr
    UINT64_C(2671779968),	// L4_ploadrht_abs
    UINT64_C(809500672),	// L4_ploadrht_rr
    UINT64_C(2671784064),	// L4_ploadrhtnew_abs
    UINT64_C(843055104),	// L4_ploadrhtnew_rr
    UINT64_C(2675976320),	// L4_ploadrif_abs
    UINT64_C(830472192),	// L4_ploadrif_rr
    UINT64_C(2675980416),	// L4_ploadrifnew_abs
    UINT64_C(864026624),	// L4_ploadrifnew_rr
    UINT64_C(2675974272),	// L4_ploadrit_abs
    UINT64_C(813694976),	// L4_ploadrit_rr
    UINT64_C(2675978368),	// L4_ploadritnew_abs
    UINT64_C(847249408),	// L4_ploadritnew_rr
    UINT64_C(2669684864),	// L4_ploadrubf_abs
    UINT64_C(824180736),	// L4_ploadrubf_rr
    UINT64_C(2669688960),	// L4_ploadrubfnew_abs
    UINT64_C(857735168),	// L4_ploadrubfnew_rr
    UINT64_C(2669682816),	// L4_ploadrubt_abs
    UINT64_C(807403520),	// L4_ploadrubt_rr
    UINT64_C(2669686912),	// L4_ploadrubtnew_abs
    UINT64_C(840957952),	// L4_ploadrubtnew_rr
    UINT64_C(2673879168),	// L4_ploadruhf_abs
    UINT64_C(828375040),	// L4_ploadruhf_rr
    UINT64_C(2673883264),	// L4_ploadruhfnew_abs
    UINT64_C(861929472),	// L4_ploadruhfnew_rr
    UINT64_C(2673877120),	// L4_ploadruht_abs
    UINT64_C(811597824),	// L4_ploadruht_rr
    UINT64_C(2673881216),	// L4_ploadruhtnew_abs
    UINT64_C(845152256),	// L4_ploadruhtnew_rr
    UINT64_C(2516582400),	// L4_return
    UINT64_C(2516594688),	// L4_return_f
    UINT64_C(2516592640),	// L4_return_fnew_pnt
    UINT64_C(2516596736),	// L4_return_fnew_pt
    UINT64_C(2516586496),	// L4_return_t
    UINT64_C(2516584448),	// L4_return_tnew_pnt
    UINT64_C(2516588544),	// L4_return_tnew_pt
    UINT64_C(1040187424),	// L4_sub_memopb_io
    UINT64_C(1042284576),	// L4_sub_memoph_io
    UINT64_C(1044381728),	// L4_sub_memopw_io
    UINT64_C(2449473600),	// L6_memcpy
    UINT64_C(18874368),	// LO
    UINT64_C(4009754656),	// M2_acci
    UINT64_C(3791650816),	// M2_accii
    UINT64_C(3875536928),	// M2_cmaci_s0
    UINT64_C(3875536960),	// M2_cmacr_s0
    UINT64_C(3875537088),	// M2_cmacs_s0
    UINT64_C(3883925696),	// M2_cmacs_s1
    UINT64_C(3879731392),	// M2_cmacsc_s0
    UINT64_C(3888120000),	// M2_cmacsc_s1
    UINT64_C(3841982496),	// M2_cmpyi_s0
    UINT64_C(3841982528),	// M2_cmpyr_s0
    UINT64_C(3978297536),	// M2_cmpyrs_s0
    UINT64_C(3986686144),	// M2_cmpyrs_s1
    UINT64_C(3982491840),	// M2_cmpyrsc_s0
    UINT64_C(3990880448),	// M2_cmpyrsc_s1
    UINT64_C(3841982656),	// M2_cmpys_s0
    UINT64_C(3850371264),	// M2_cmpys_s1
    UINT64_C(3846176960),	// M2_cmpysc_s0
    UINT64_C(3854565568),	// M2_cmpysc_s1
    UINT64_C(3875537120),	// M2_cnacs_s0
    UINT64_C(3883925728),	// M2_cnacs_s1
    UINT64_C(3879731424),	// M2_cnacsc_s0
    UINT64_C(3888120032),	// M2_cnacsc_s1
    UINT64_C(3875536896),	// M2_dpmpyss_acc_s0
    UINT64_C(3877634048),	// M2_dpmpyss_nac_s0
    UINT64_C(3978297376),	// M2_dpmpyss_rnd_s0
    UINT64_C(3841982464),	// M2_dpmpyss_s0
    UINT64_C(3879731200),	// M2_dpmpyuu_acc_s0
    UINT64_C(3881828352),	// M2_dpmpyuu_nac_s0
    UINT64_C(3846176768),	// M2_dpmpyuu_s0
    UINT64_C(3986686080),	// M2_hmmpyh_rs1
    UINT64_C(3986685952),	// M2_hmmpyh_s1
    UINT64_C(3990880384),	// M2_hmmpyl_rs1
    UINT64_C(3986685984),	// M2_hmmpyl_s1
    UINT64_C(4009754624),	// M2_maci
    UINT64_C(3783262208),	// M2_macsin
    UINT64_C(3774873600),	// M2_macsip
    UINT64_C(3927965920),	// M2_mmachs_rs0
    UINT64_C(3936354528),	// M2_mmachs_rs1
    UINT64_C(3925868768),	// M2_mmachs_s0
    UINT64_C(3934257376),	// M2_mmachs_s1
    UINT64_C(3927965856),	// M2_mmacls_rs0
    UINT64_C(3936354464),	// M2_mmacls_rs1
    UINT64_C(3925868704),	// M2_mmacls_s0
    UINT64_C(3934257312),	// M2_mmacls_s1
    UINT64_C(3932160224),	// M2_mmacuhs_rs0
    UINT64_C(3940548832),	// M2_mmacuhs_rs1
    UINT64_C(3930063072),	// M2_mmacuhs_s0
    UINT64_C(3938451680),	// M2_mmacuhs_s1
    UINT64_C(3932160160),	// M2_mmaculs_rs0
    UINT64_C(3940548768),	// M2_mmaculs_rs1
    UINT64_C(3930063008),	// M2_mmaculs_s0
    UINT64_C(3938451616),	// M2_mmaculs_s1
    UINT64_C(3894411488),	// M2_mmpyh_rs0
    UINT64_C(3902800096),	// M2_mmpyh_rs1
    UINT64_C(3892314336),	// M2_mmpyh_s0
    UINT64_C(3900702944),	// M2_mmpyh_s1
    UINT64_C(3894411424),	// M2_mmpyl_rs0
    UINT64_C(3902800032),	// M2_mmpyl_rs1
    UINT64_C(3892314272),	// M2_mmpyl_s0
    UINT64_C(3900702880),	// M2_mmpyl_s1
    UINT64_C(3898605792),	// M2_mmpyuh_rs0
    UINT64_C(3906994400),	// M2_mmpyuh_rs1
    UINT64_C(3896508640),	// M2_mmpyuh_s0
    UINT64_C(3904897248),	// M2_mmpyuh_s1
    UINT64_C(3898605728),	// M2_mmpyul_rs0
    UINT64_C(3906994336),	// M2_mmpyul_rs1
    UINT64_C(3896508576),	// M2_mmpyul_s0
    UINT64_C(3904897184),	// M2_mmpyul_s1
    UINT64_C(4018143232),	// M2_mnaci
    UINT64_C(3992977504),	// M2_mpy_acc_hh_s0
    UINT64_C(4001366112),	// M2_mpy_acc_hh_s1
    UINT64_C(3992977472),	// M2_mpy_acc_hl_s0
    UINT64_C(4001366080),	// M2_mpy_acc_hl_s1
    UINT64_C(3992977440),	// M2_mpy_acc_lh_s0
    UINT64_C(4001366048),	// M2_mpy_acc_lh_s1
    UINT64_C(3992977408),	// M2_mpy_acc_ll_s0
    UINT64_C(4001366016),	// M2_mpy_acc_ll_s1
    UINT64_C(3992977632),	// M2_mpy_acc_sat_hh_s0
    UINT64_C(4001366240),	// M2_mpy_acc_sat_hh_s1
    UINT64_C(3992977600),	// M2_mpy_acc_sat_hl_s0
    UINT64_C(4001366208),	// M2_mpy_acc_sat_hl_s1
    UINT64_C(3992977568),	// M2_mpy_acc_sat_lh_s0
    UINT64_C(4001366176),	// M2_mpy_acc_sat_lh_s1
    UINT64_C(3992977536),	// M2_mpy_acc_sat_ll_s0
    UINT64_C(4001366144),	// M2_mpy_acc_sat_ll_s1
    UINT64_C(3959423072),	// M2_mpy_hh_s0
    UINT64_C(3967811680),	// M2_mpy_hh_s1
    UINT64_C(3959423040),	// M2_mpy_hl_s0
    UINT64_C(3967811648),	// M2_mpy_hl_s1
    UINT64_C(3959423008),	// M2_mpy_lh_s0
    UINT64_C(3967811616),	// M2_mpy_lh_s1
    UINT64_C(3959422976),	// M2_mpy_ll_s0
    UINT64_C(3967811584),	// M2_mpy_ll_s1
    UINT64_C(3995074656),	// M2_mpy_nac_hh_s0
    UINT64_C(4003463264),	// M2_mpy_nac_hh_s1
    UINT64_C(3995074624),	// M2_mpy_nac_hl_s0
    UINT64_C(4003463232),	// M2_mpy_nac_hl_s1
    UINT64_C(3995074592),	// M2_mpy_nac_lh_s0
    UINT64_C(4003463200),	// M2_mpy_nac_lh_s1
    UINT64_C(3995074560),	// M2_mpy_nac_ll_s0
    UINT64_C(4003463168),	// M2_mpy_nac_ll_s1
    UINT64_C(3995074784),	// M2_mpy_nac_sat_hh_s0
    UINT64_C(4003463392),	// M2_mpy_nac_sat_hh_s1
    UINT64_C(3995074752),	// M2_mpy_nac_sat_hl_s0
    UINT64_C(4003463360),	// M2_mpy_nac_sat_hl_s1
    UINT64_C(3995074720),	// M2_mpy_nac_sat_lh_s0
    UINT64_C(4003463328),	// M2_mpy_nac_sat_lh_s1
    UINT64_C(3995074688),	// M2_mpy_nac_sat_ll_s0
    UINT64_C(4003463296),	// M2_mpy_nac_sat_ll_s1
    UINT64_C(3961520224),	// M2_mpy_rnd_hh_s0
    UINT64_C(3969908832),	// M2_mpy_rnd_hh_s1
    UINT64_C(3961520192),	// M2_mpy_rnd_hl_s0
    UINT64_C(3969908800),	// M2_mpy_rnd_hl_s1
    UINT64_C(3961520160),	// M2_mpy_rnd_lh_s0
    UINT64_C(3969908768),	// M2_mpy_rnd_lh_s1
    UINT64_C(3961520128),	// M2_mpy_rnd_ll_s0
    UINT64_C(3969908736),	// M2_mpy_rnd_ll_s1
    UINT64_C(3959423200),	// M2_mpy_sat_hh_s0
    UINT64_C(3967811808),	// M2_mpy_sat_hh_s1
    UINT64_C(3959423168),	// M2_mpy_sat_hl_s0
    UINT64_C(3967811776),	// M2_mpy_sat_hl_s1
    UINT64_C(3959423136),	// M2_mpy_sat_lh_s0
    UINT64_C(3967811744),	// M2_mpy_sat_lh_s1
    UINT64_C(3959423104),	// M2_mpy_sat_ll_s0
    UINT64_C(3967811712),	// M2_mpy_sat_ll_s1
    UINT64_C(3961520352),	// M2_mpy_sat_rnd_hh_s0
    UINT64_C(3969908960),	// M2_mpy_sat_rnd_hh_s1
    UINT64_C(3961520320),	// M2_mpy_sat_rnd_hl_s0
    UINT64_C(3969908928),	// M2_mpy_sat_rnd_hl_s1
    UINT64_C(3961520288),	// M2_mpy_sat_rnd_lh_s0
    UINT64_C(3969908896),	// M2_mpy_sat_rnd_lh_s1
    UINT64_C(3961520256),	// M2_mpy_sat_rnd_ll_s0
    UINT64_C(3969908864),	// M2_mpy_sat_rnd_ll_s1
    UINT64_C(3976200224),	// M2_mpy_up
    UINT64_C(3986686016),	// M2_mpy_up_s1
    UINT64_C(3990880256),	// M2_mpy_up_s1_sat
    UINT64_C(3858759776),	// M2_mpyd_acc_hh_s0
    UINT64_C(3867148384),	// M2_mpyd_acc_hh_s1
    UINT64_C(3858759744),	// M2_mpyd_acc_hl_s0
    UINT64_C(3867148352),	// M2_mpyd_acc_hl_s1
    UINT64_C(3858759712),	// M2_mpyd_acc_lh_s0
    UINT64_C(3867148320),	// M2_mpyd_acc_lh_s1
    UINT64_C(3858759680),	// M2_mpyd_acc_ll_s0
    UINT64_C(3867148288),	// M2_mpyd_acc_ll_s1
    UINT64_C(3825205344),	// M2_mpyd_hh_s0
    UINT64_C(3833593952),	// M2_mpyd_hh_s1
    UINT64_C(3825205312),	// M2_mpyd_hl_s0
    UINT64_C(3833593920),	// M2_mpyd_hl_s1
    UINT64_C(3825205280),	// M2_mpyd_lh_s0
    UINT64_C(3833593888),	// M2_mpyd_lh_s1
    UINT64_C(3825205248),	// M2_mpyd_ll_s0
    UINT64_C(3833593856),	// M2_mpyd_ll_s1
    UINT64_C(3860856928),	// M2_mpyd_nac_hh_s0
    UINT64_C(3869245536),	// M2_mpyd_nac_hh_s1
    UINT64_C(3860856896),	// M2_mpyd_nac_hl_s0
    UINT64_C(3869245504),	// M2_mpyd_nac_hl_s1
    UINT64_C(3860856864),	// M2_mpyd_nac_lh_s0
    UINT64_C(3869245472),	// M2_mpyd_nac_lh_s1
    UINT64_C(3860856832),	// M2_mpyd_nac_ll_s0
    UINT64_C(3869245440),	// M2_mpyd_nac_ll_s1
    UINT64_C(3827302496),	// M2_mpyd_rnd_hh_s0
    UINT64_C(3835691104),	// M2_mpyd_rnd_hh_s1
    UINT64_C(3827302464),	// M2_mpyd_rnd_hl_s0
    UINT64_C(3835691072),	// M2_mpyd_rnd_hl_s1
    UINT64_C(3827302432),	// M2_mpyd_rnd_lh_s0
    UINT64_C(3835691040),	// M2_mpyd_rnd_lh_s1
    UINT64_C(3827302400),	// M2_mpyd_rnd_ll_s0
    UINT64_C(3835691008),	// M2_mpyd_rnd_ll_s1
    UINT64_C(3976200192),	// M2_mpyi
    UINT64_C(3766484992),	// M2_mpysin
    UINT64_C(3758096384),	// M2_mpysip
    UINT64_C(3982491680),	// M2_mpysu_up
    UINT64_C(3997171808),	// M2_mpyu_acc_hh_s0
    UINT64_C(4005560416),	// M2_mpyu_acc_hh_s1
    UINT64_C(3997171776),	// M2_mpyu_acc_hl_s0
    UINT64_C(4005560384),	// M2_mpyu_acc_hl_s1
    UINT64_C(3997171744),	// M2_mpyu_acc_lh_s0
    UINT64_C(4005560352),	// M2_mpyu_acc_lh_s1
    UINT64_C(3997171712),	// M2_mpyu_acc_ll_s0
    UINT64_C(4005560320),	// M2_mpyu_acc_ll_s1
    UINT64_C(3963617376),	// M2_mpyu_hh_s0
    UINT64_C(3972005984),	// M2_mpyu_hh_s1
    UINT64_C(3963617344),	// M2_mpyu_hl_s0
    UINT64_C(3972005952),	// M2_mpyu_hl_s1
    UINT64_C(3963617312),	// M2_mpyu_lh_s0
    UINT64_C(3972005920),	// M2_mpyu_lh_s1
    UINT64_C(3963617280),	// M2_mpyu_ll_s0
    UINT64_C(3972005888),	// M2_mpyu_ll_s1
    UINT64_C(3999268960),	// M2_mpyu_nac_hh_s0
    UINT64_C(4007657568),	// M2_mpyu_nac_hh_s1
    UINT64_C(3999268928),	// M2_mpyu_nac_hl_s0
    UINT64_C(4007657536),	// M2_mpyu_nac_hl_s1
    UINT64_C(3999268896),	// M2_mpyu_nac_lh_s0
    UINT64_C(4007657504),	// M2_mpyu_nac_lh_s1
    UINT64_C(3999268864),	// M2_mpyu_nac_ll_s0
    UINT64_C(4007657472),	// M2_mpyu_nac_ll_s1
    UINT64_C(3980394528),	// M2_mpyu_up
    UINT64_C(3862954080),	// M2_mpyud_acc_hh_s0
    UINT64_C(3871342688),	// M2_mpyud_acc_hh_s1
    UINT64_C(3862954048),	// M2_mpyud_acc_hl_s0
    UINT64_C(3871342656),	// M2_mpyud_acc_hl_s1
    UINT64_C(3862954016),	// M2_mpyud_acc_lh_s0
    UINT64_C(3871342624),	// M2_mpyud_acc_lh_s1
    UINT64_C(3862953984),	// M2_mpyud_acc_ll_s0
    UINT64_C(3871342592),	// M2_mpyud_acc_ll_s1
    UINT64_C(3829399648),	// M2_mpyud_hh_s0
    UINT64_C(3837788256),	// M2_mpyud_hh_s1
    UINT64_C(3829399616),	// M2_mpyud_hl_s0
    UINT64_C(3837788224),	// M2_mpyud_hl_s1
    UINT64_C(3829399584),	// M2_mpyud_lh_s0
    UINT64_C(3837788192),	// M2_mpyud_lh_s1
    UINT64_C(3829399552),	// M2_mpyud_ll_s0
    UINT64_C(3837788160),	// M2_mpyud_ll_s1
    UINT64_C(3865051232),	// M2_mpyud_nac_hh_s0
    UINT64_C(3873439840),	// M2_mpyud_nac_hh_s1
    UINT64_C(3865051200),	// M2_mpyud_nac_hl_s0
    UINT64_C(3873439808),	// M2_mpyud_nac_hl_s1
    UINT64_C(3865051168),	// M2_mpyud_nac_lh_s0
    UINT64_C(3873439776),	// M2_mpyud_nac_lh_s1
    UINT64_C(3865051136),	// M2_mpyud_nac_ll_s0
    UINT64_C(3873439744),	// M2_mpyud_nac_ll_s1
    UINT64_C(4018143264),	// M2_nacci
    UINT64_C(3800039424),	// M2_naccii
    UINT64_C(4009754720),	// M2_subacc
    UINT64_C(3898605568),	// M2_vabsdiffh
    UINT64_C(3894411264),	// M2_vabsdiffw
    UINT64_C(3930062976),	// M2_vcmac_s0_sat_i
    UINT64_C(3927965824),	// M2_vcmac_s0_sat_r
    UINT64_C(3896508608),	// M2_vcmpy_s0_sat_i
    UINT64_C(3894411456),	// M2_vcmpy_s0_sat_r
    UINT64_C(3904897216),	// M2_vcmpy_s1_sat_i
    UINT64_C(3902800064),	// M2_vcmpy_s1_sat_r
    UINT64_C(3925868672),	// M2_vdmacs_s0
    UINT64_C(3934257280),	// M2_vdmacs_s1
    UINT64_C(3909091328),	// M2_vdmpyrs_s0
    UINT64_C(3917479936),	// M2_vdmpyrs_s1
    UINT64_C(3892314240),	// M2_vdmpys_s0
    UINT64_C(3900702848),	// M2_vdmpys_s1
    UINT64_C(3877634080),	// M2_vmac2
    UINT64_C(3927965760),	// M2_vmac2es
    UINT64_C(3925868736),	// M2_vmac2es_s0
    UINT64_C(3934257344),	// M2_vmac2es_s1
    UINT64_C(3875537056),	// M2_vmac2s_s0
    UINT64_C(3883925664),	// M2_vmac2s_s1
    UINT64_C(3881828512),	// M2_vmac2su_s0
    UINT64_C(3890217120),	// M2_vmac2su_s1
    UINT64_C(3892314304),	// M2_vmpy2es_s0
    UINT64_C(3900702912),	// M2_vmpy2es_s1
    UINT64_C(3841982624),	// M2_vmpy2s_s0
    UINT64_C(3978297568),	// M2_vmpy2s_s0pack
    UINT64_C(3850371232),	// M2_vmpy2s_s1
    UINT64_C(3986686176),	// M2_vmpy2s_s1pack
    UINT64_C(3841982688),	// M2_vmpy2su_s0
    UINT64_C(3850371296),	// M2_vmpy2su_s1
    UINT64_C(3911188704),	// M2_vraddh
    UINT64_C(3909091360),	// M2_vradduh
    UINT64_C(3925868544),	// M2_vrcmaci_s0
    UINT64_C(3930062848),	// M2_vrcmaci_s0c
    UINT64_C(3925868576),	// M2_vrcmacr_s0
    UINT64_C(3932160032),	// M2_vrcmacr_s0c
    UINT64_C(3892314112),	// M2_vrcmpyi_s0
    UINT64_C(3896508416),	// M2_vrcmpyi_s0c
    UINT64_C(3892314144),	// M2_vrcmpyr_s0
    UINT64_C(3898605600),	// M2_vrcmpyr_s0c
    UINT64_C(3936354432),	// M2_vrcmpys_acc_s1_h
    UINT64_C(3940548736),	// M2_vrcmpys_acc_s1_l
    UINT64_C(3902800000),	// M2_vrcmpys_s1_h
    UINT64_C(3906994304),	// M2_vrcmpys_s1_l
    UINT64_C(3919577280),	// M2_vrcmpys_s1rp_h
    UINT64_C(3919577312),	// M2_vrcmpys_s1rp_l
    UINT64_C(3925868608),	// M2_vrmac_s0
    UINT64_C(3892314176),	// M2_vrmpy_s0
    UINT64_C(4018143328),	// M2_xor_xacc
    UINT64_C(4013948928),	// M4_and_and
    UINT64_C(4011851808),	// M4_and_andn
    UINT64_C(4013948960),	// M4_and_or
    UINT64_C(4013948992),	// M4_and_xor
    UINT64_C(3305111680),	// M4_cmpyi_wh
    UINT64_C(3305111712),	// M4_cmpyi_whc
    UINT64_C(3305111744),	// M4_cmpyr_wh
    UINT64_C(3305111776),	// M4_cmpyr_whc
    UINT64_C(4016046080),	// M4_mac_up_s1_sat
    UINT64_C(3623878656),	// M4_mpyri_addi
    UINT64_C(3749707776),	// M4_mpyri_addr
    UINT64_C(3741319168),	// M4_mpyri_addr_u2
    UINT64_C(3607101440),	// M4_mpyrr_addi
    UINT64_C(3808428032),	// M4_mpyrr_addr
    UINT64_C(4016046112),	// M4_nac_up_s1_sat
    UINT64_C(4013949024),	// M4_or_and
    UINT64_C(4011851776),	// M4_or_andn
    UINT64_C(4022337536),	// M4_or_or
    UINT64_C(4022337568),	// M4_or_xor
    UINT64_C(3846176992),	// M4_pmpyw
    UINT64_C(3877634272),	// M4_pmpyw_acc
    UINT64_C(3854565600),	// M4_vpmpyh
    UINT64_C(3886022880),	// M4_vpmpyh_acc
    UINT64_C(3927965888),	// M4_vrmpyeh_acc_s0
    UINT64_C(3936354496),	// M4_vrmpyeh_acc_s1
    UINT64_C(3896508544),	// M4_vrmpyeh_s0
    UINT64_C(3904897152),	// M4_vrmpyeh_s1
    UINT64_C(3932160192),	// M4_vrmpyoh_acc_s0
    UINT64_C(3940548800),	// M4_vrmpyoh_acc_s1
    UINT64_C(3894411328),	// M4_vrmpyoh_s0
    UINT64_C(3902799936),	// M4_vrmpyoh_s1
    UINT64_C(4022337600),	// M4_xor_and
    UINT64_C(4011851840),	// M4_xor_andn
    UINT64_C(4022337632),	// M4_xor_or
    UINT64_C(3397386240),	// M4_xor_xacc
    UINT64_C(3927965728),	// M5_vdmacbsu
    UINT64_C(3902799904),	// M5_vdmpybsu
    UINT64_C(3888119840),	// M5_vmacbsu
    UINT64_C(3883925536),	// M5_vmacbuu
    UINT64_C(3846176800),	// M5_vmpybsu
    UINT64_C(3850371104),	// M5_vmpybuu
    UINT64_C(3938451488),	// M5_vrmacbsu
    UINT64_C(3934257184),	// M5_vrmacbuu
    UINT64_C(3904897056),	// M5_vrmpybsu
    UINT64_C(3900702752),	// M5_vrmpybuu
    UINT64_C(3906994176),	// M6_vabsdiffb
    UINT64_C(3902799872),	// M6_vabsdiffub
    UINT64_C(3898605632),	// M7_dcmpyiw
    UINT64_C(3932160064),	// M7_dcmpyiw_acc
    UINT64_C(3906994240),	// M7_dcmpyiwc
    UINT64_C(3930063040),	// M7_dcmpyiwc_acc
    UINT64_C(3900702784),	// M7_dcmpyrw
    UINT64_C(3934257216),	// M7_dcmpyrw_acc
    UINT64_C(3904897088),	// M7_dcmpyrwc
    UINT64_C(3938451520),	// M7_dcmpyrwc_acc
    UINT64_C(3911188480),	// M7_wcmpyiw
    UINT64_C(3919577088),	// M7_wcmpyiw_rnd
    UINT64_C(3909091456),	// M7_wcmpyiwc
    UINT64_C(3917480064),	// M7_wcmpyiwc_rnd
    UINT64_C(3913285632),	// M7_wcmpyrw
    UINT64_C(3921674240),	// M7_wcmpyrw_rnd
    UINT64_C(3915382784),	// M7_wcmpyrwc
    UINT64_C(3923771392),	// M7_wcmpyrwc_rnd
    UINT64_C(1509949440),	// PS_call_stk
    UINT64_C(1352663040),	// PS_callr_nr
    UINT64_C(1384120320),	// PS_jmpret
    UINT64_C(1398800384),	// PS_jmpretf
    UINT64_C(1398802432),	// PS_jmpretfnew
    UINT64_C(1398806528),	// PS_jmpretfnewpt
    UINT64_C(1396703232),	// PS_jmprett
    UINT64_C(1396705280),	// PS_jmprettnew
    UINT64_C(1396709376),	// PS_jmprettnewpt
    UINT64_C(1224736768),	// PS_loadrbabs
    UINT64_C(1237319680),	// PS_loadrdabs
    UINT64_C(1228931072),	// PS_loadrhabs
    UINT64_C(1233125376),	// PS_loadriabs
    UINT64_C(1226833920),	// PS_loadrubabs
    UINT64_C(1231028224),	// PS_loadruhabs
    UINT64_C(1207959552),	// PS_storerbabs
    UINT64_C(1218445312),	// PS_storerbnewabs
    UINT64_C(1220542464),	// PS_storerdabs
    UINT64_C(1214251008),	// PS_storerfabs
    UINT64_C(1212153856),	// PS_storerhabs
    UINT64_C(1218447360),	// PS_storerhnewabs
    UINT64_C(1216348160),	// PS_storeriabs
    UINT64_C(1218449408),	// PS_storerinewabs
    UINT64_C(1417674752),	// PS_trap1
    UINT64_C(2699034636),	// R6_release_at_vi
    UINT64_C(2699034668),	// R6_release_st_vi
    UINT64_C(1509949440),	// RESTORE_DEALLOC_BEFORE_TAILCALL_V4
    UINT64_C(1509949440),	// RESTORE_DEALLOC_BEFORE_TAILCALL_V4_EXT
    UINT64_C(1509949440),	// RESTORE_DEALLOC_BEFORE_TAILCALL_V4_EXT_PIC
    UINT64_C(1509949440),	// RESTORE_DEALLOC_BEFORE_TAILCALL_V4_PIC
    UINT64_C(1476395008),	// RESTORE_DEALLOC_RET_JMP_V4
    UINT64_C(1476395008),	// RESTORE_DEALLOC_RET_JMP_V4_EXT
    UINT64_C(1476395008),	// RESTORE_DEALLOC_RET_JMP_V4_EXT_PIC
    UINT64_C(1476395008),	// RESTORE_DEALLOC_RET_JMP_V4_PIC
    UINT64_C(3288334336),	// S2_addasl_rrri
    UINT64_C(2692743168),	// S2_allocframe
    UINT64_C(2147483712),	// S2_asl_i_p
    UINT64_C(2181038272),	// S2_asl_i_p_acc
    UINT64_C(2185232448),	// S2_asl_i_p_and
    UINT64_C(2181038144),	// S2_asl_i_p_nac
    UINT64_C(2185232576),	// S2_asl_i_p_or
    UINT64_C(2189426752),	// S2_asl_i_p_xacc
    UINT64_C(2348810304),	// S2_asl_i_r
    UINT64_C(2382364864),	// S2_asl_i_r_acc
    UINT64_C(2386559040),	// S2_asl_i_r_and
    UINT64_C(2382364736),	// S2_asl_i_r_nac
    UINT64_C(2386559168),	// S2_asl_i_r_or
    UINT64_C(2353004608),	// S2_asl_i_r_sat
    UINT64_C(2390753344),	// S2_asl_i_r_xacc
    UINT64_C(2155872320),	// S2_asl_i_vh
    UINT64_C(2151678016),	// S2_asl_i_vw
    UINT64_C(3279945856),	// S2_asl_r_p
    UINT64_C(3418357888),	// S2_asl_r_p_acc
    UINT64_C(3409969280),	// S2_asl_r_p_and
    UINT64_C(3414163584),	// S2_asl_r_p_nac
    UINT64_C(3405774976),	// S2_asl_r_p_or
    UINT64_C(3412066432),	// S2_asl_r_p_xor
    UINT64_C(3326083200),	// S2_asl_r_r
    UINT64_C(3435135104),	// S2_asl_r_r_acc
    UINT64_C(3426746496),	// S2_asl_r_r_and
    UINT64_C(3430940800),	// S2_asl_r_r_nac
    UINT64_C(3422552192),	// S2_asl_r_r_or
    UINT64_C(3321888896),	// S2_asl_r_r_sat
    UINT64_C(3275751552),	// S2_asl_r_vh
    UINT64_C(3271557248),	// S2_asl_r_vw
    UINT64_C(2147483648),	// S2_asr_i_p
    UINT64_C(2181038208),	// S2_asr_i_p_acc
    UINT64_C(2185232384),	// S2_asr_i_p_and
    UINT64_C(2181038080),	// S2_asr_i_p_nac
    UINT64_C(2185232512),	// S2_asr_i_p_or
    UINT64_C(2160066784),	// S2_asr_i_p_rnd
    UINT64_C(2348810240),	// S2_asr_i_r
    UINT64_C(2382364800),	// S2_asr_i_r_acc
    UINT64_C(2386558976),	// S2_asr_i_r_and
    UINT64_C(2382364672),	// S2_asr_i_r_nac
    UINT64_C(2386559104),	// S2_asr_i_r_or
    UINT64_C(2353004544),	// S2_asr_i_r_rnd
    UINT64_C(2294284352),	// S2_asr_i_svw_trun
    UINT64_C(2155872256),	// S2_asr_i_vh
    UINT64_C(2151677952),	// S2_asr_i_vw
    UINT64_C(3279945728),	// S2_asr_r_p
    UINT64_C(3418357760),	// S2_asr_r_p_acc
    UINT64_C(3409969152),	// S2_asr_r_p_and
    UINT64_C(3414163456),	// S2_asr_r_p_nac
    UINT64_C(3405774848),	// S2_asr_r_p_or
    UINT64_C(3412066304),	// S2_asr_r_p_xor
    UINT64_C(3326083072),	// S2_asr_r_r
    UINT64_C(3435134976),	// S2_asr_r_r_acc
    UINT64_C(3426746368),	// S2_asr_r_r_and
    UINT64_C(3430940672),	// S2_asr_r_r_nac
    UINT64_C(3422552064),	// S2_asr_r_r_or
    UINT64_C(3321888768),	// S2_asr_r_r_sat
    UINT64_C(3305111616),	// S2_asr_r_svw_trun
    UINT64_C(3275751424),	// S2_asr_r_vh
    UINT64_C(3271557120),	// S2_asr_r_vw
    UINT64_C(2353004736),	// S2_brev
    UINT64_C(2160066752),	// S2_brevp
    UINT64_C(3250585792),	// S2_cabacdecbin
    UINT64_C(2348810400),	// S2_cl0
    UINT64_C(2285895744),	// S2_cl0p
    UINT64_C(2348810432),	// S2_cl1
    UINT64_C(2285895808),	// S2_cl1p
    UINT64_C(2348810368),	// S2_clb
    UINT64_C(2348810464),	// S2_clbnorm
    UINT64_C(2285895680),	// S2_clbp
    UINT64_C(2361393184),	// S2_clrbit_i
    UINT64_C(3330277440),	// S2_clrbit_r
    UINT64_C(2353004672),	// S2_ct0
    UINT64_C(2296381504),	// S2_ct0p
    UINT64_C(2353004704),	// S2_ct1
    UINT64_C(2296381568),	// S2_ct1p
    UINT64_C(2160066688),	// S2_deinterleave
    UINT64_C(2365587456),	// S2_extractu
    UINT64_C(3372220416),	// S2_extractu_rp
    UINT64_C(2164260864),	// S2_extractup
    UINT64_C(3238002688),	// S2_extractup_rp
    UINT64_C(2399141888),	// S2_insert
    UINT64_C(3355443200),	// S2_insert_rp
    UINT64_C(2197815296),	// S2_insertp
    UINT64_C(3388997632),	// S2_insertp_rp
    UINT64_C(2160066720),	// S2_interleave
    UINT64_C(3246391488),	// S2_lfsp
    UINT64_C(3279945920),	// S2_lsl_r_p
    UINT64_C(3418357952),	// S2_lsl_r_p_acc
    UINT64_C(3409969344),	// S2_lsl_r_p_and
    UINT64_C(3414163648),	// S2_lsl_r_p_nac
    UINT64_C(3405775040),	// S2_lsl_r_p_or
    UINT64_C(3412066496),	// S2_lsl_r_p_xor
    UINT64_C(3326083264),	// S2_lsl_r_r
    UINT64_C(3435135168),	// S2_lsl_r_r_acc
    UINT64_C(3426746560),	// S2_lsl_r_r_and
    UINT64_C(3430940864),	// S2_lsl_r_r_nac
    UINT64_C(3422552256),	// S2_lsl_r_r_or
    UINT64_C(3275751616),	// S2_lsl_r_vh
    UINT64_C(3271557312),	// S2_lsl_r_vw
    UINT64_C(2147483680),	// S2_lsr_i_p
    UINT64_C(2181038240),	// S2_lsr_i_p_acc
    UINT64_C(2185232416),	// S2_lsr_i_p_and
    UINT64_C(2181038112),	// S2_lsr_i_p_nac
    UINT64_C(2185232544),	// S2_lsr_i_p_or
    UINT64_C(2189426720),	// S2_lsr_i_p_xacc
    UINT64_C(2348810272),	// S2_lsr_i_r
    UINT64_C(2382364832),	// S2_lsr_i_r_acc
    UINT64_C(2386559008),	// S2_lsr_i_r_and
    UINT64_C(2382364704),	// S2_lsr_i_r_nac
    UINT64_C(2386559136),	// S2_lsr_i_r_or
    UINT64_C(2390753312),	// S2_lsr_i_r_xacc
    UINT64_C(2155872288),	// S2_lsr_i_vh
    UINT64_C(2151677984),	// S2_lsr_i_vw
    UINT64_C(3279945792),	// S2_lsr_r_p
    UINT64_C(3418357824),	// S2_lsr_r_p_acc
    UINT64_C(3409969216),	// S2_lsr_r_p_and
    UINT64_C(3414163520),	// S2_lsr_r_p_nac
    UINT64_C(3405774912),	// S2_lsr_r_p_or
    UINT64_C(3412066368),	// S2_lsr_r_p_xor
    UINT64_C(3326083136),	// S2_lsr_r_r
    UINT64_C(3435135040),	// S2_lsr_r_r_acc
    UINT64_C(3426746432),	// S2_lsr_r_r_and
    UINT64_C(3430940736),	// S2_lsr_r_r_nac
    UINT64_C(3422552128),	// S2_lsr_r_r_or
    UINT64_C(3275751488),	// S2_lsr_r_vh
    UINT64_C(3271557184),	// S2_lsr_r_vw
    UINT64_C(2365595648),	// S2_mask
    UINT64_C(4118806528),	// S2_packhl
    UINT64_C(3489660928),	// S2_parityp
    UINT64_C(1140850688),	// S2_pstorerbf_io
    UINT64_C(2868912132),	// S2_pstorerbf_pi
    UINT64_C(2868912260),	// S2_pstorerbfnew_pi
    UINT64_C(1151336448),	// S2_pstorerbnewf_io
    UINT64_C(2879397892),	// S2_pstorerbnewf_pi
    UINT64_C(2879398020),	// S2_pstorerbnewfnew_pi
    UINT64_C(1084227584),	// S2_pstorerbnewt_io
    UINT64_C(2879397888),	// S2_pstorerbnewt_pi
    UINT64_C(2879398016),	// S2_pstorerbnewtnew_pi
    UINT64_C(1073741824),	// S2_pstorerbt_io
    UINT64_C(2868912128),	// S2_pstorerbt_pi
    UINT64_C(2868912256),	// S2_pstorerbtnew_pi
    UINT64_C(1153433600),	// S2_pstorerdf_io
    UINT64_C(2881495044),	// S2_pstorerdf_pi
    UINT64_C(2881495172),	// S2_pstorerdfnew_pi
    UINT64_C(1086324736),	// S2_pstorerdt_io
    UINT64_C(2881495040),	// S2_pstorerdt_pi
    UINT64_C(2881495168),	// S2_pstorerdtnew_pi
    UINT64_C(1147142144),	// S2_pstorerff_io
    UINT64_C(2875203588),	// S2_pstorerff_pi
    UINT64_C(2875203716),	// S2_pstorerffnew_pi
    UINT64_C(1080033280),	// S2_pstorerft_io
    UINT64_C(2875203584),	// S2_pstorerft_pi
    UINT64_C(2875203712),	// S2_pstorerftnew_pi
    UINT64_C(1145044992),	// S2_pstorerhf_io
    UINT64_C(2873106436),	// S2_pstorerhf_pi
    UINT64_C(2873106564),	// S2_pstorerhfnew_pi
    UINT64_C(1151338496),	// S2_pstorerhnewf_io
    UINT64_C(2879399940),	// S2_pstorerhnewf_pi
    UINT64_C(2879400068),	// S2_pstorerhnewfnew_pi
    UINT64_C(1084229632),	// S2_pstorerhnewt_io
    UINT64_C(2879399936),	// S2_pstorerhnewt_pi
    UINT64_C(2879400064),	// S2_pstorerhnewtnew_pi
    UINT64_C(1077936128),	// S2_pstorerht_io
    UINT64_C(2873106432),	// S2_pstorerht_pi
    UINT64_C(2873106560),	// S2_pstorerhtnew_pi
    UINT64_C(1149239296),	// S2_pstorerif_io
    UINT64_C(2877300740),	// S2_pstorerif_pi
    UINT64_C(2877300868),	// S2_pstorerifnew_pi
    UINT64_C(1151340544),	// S2_pstorerinewf_io
    UINT64_C(2879401988),	// S2_pstorerinewf_pi
    UINT64_C(2879402116),	// S2_pstorerinewfnew_pi
    UINT64_C(1084231680),	// S2_pstorerinewt_io
    UINT64_C(2879401984),	// S2_pstorerinewt_pi
    UINT64_C(2879402112),	// S2_pstorerinewtnew_pi
    UINT64_C(1082130432),	// S2_pstorerit_io
    UINT64_C(2877300736),	// S2_pstorerit_pi
    UINT64_C(2877300864),	// S2_pstoreritnew_pi
    UINT64_C(2361393152),	// S2_setbit_i
    UINT64_C(3330277376),	// S2_setbit_r
    UINT64_C(3238002752),	// S2_shuffeb
    UINT64_C(3238002880),	// S2_shuffeh
    UINT64_C(3238002816),	// S2_shuffob
    UINT64_C(3246391296),	// S2_shuffoh
    UINT64_C(2701131776),	// S2_storerb_io
    UINT64_C(2936012800),	// S2_storerb_pbr
    UINT64_C(2835349504),	// S2_storerb_pci
    UINT64_C(2835349506),	// S2_storerb_pcr
    UINT64_C(2868903936),	// S2_storerb_pi
    UINT64_C(2902458368),	// S2_storerb_pr
    UINT64_C(1207959552),	// S2_storerbgp
    UINT64_C(2711617536),	// S2_storerbnew_io
    UINT64_C(2946498560),	// S2_storerbnew_pbr
    UINT64_C(2845835264),	// S2_storerbnew_pci
    UINT64_C(2845835266),	// S2_storerbnew_pcr
    UINT64_C(2879389696),	// S2_storerbnew_pi
    UINT64_C(2912944128),	// S2_storerbnew_pr
    UINT64_C(1218445312),	// S2_storerbnewgp
    UINT64_C(2713714688),	// S2_storerd_io
    UINT64_C(2948595712),	// S2_storerd_pbr
    UINT64_C(2847932416),	// S2_storerd_pci
    UINT64_C(2847932418),	// S2_storerd_pcr
    UINT64_C(2881486848),	// S2_storerd_pi
    UINT64_C(2915041280),	// S2_storerd_pr
    UINT64_C(1220542464),	// S2_storerdgp
    UINT64_C(2707423232),	// S2_storerf_io
    UINT64_C(2942304256),	// S2_storerf_pbr
    UINT64_C(2841640960),	// S2_storerf_pci
    UINT64_C(2841640962),	// S2_storerf_pcr
    UINT64_C(2875195392),	// S2_storerf_pi
    UINT64_C(2908749824),	// S2_storerf_pr
    UINT64_C(1214251008),	// S2_storerfgp
    UINT64_C(2705326080),	// S2_storerh_io
    UINT64_C(2940207104),	// S2_storerh_pbr
    UINT64_C(2839543808),	// S2_storerh_pci
    UINT64_C(2839543810),	// S2_storerh_pcr
    UINT64_C(2873098240),	// S2_storerh_pi
    UINT64_C(2906652672),	// S2_storerh_pr
    UINT64_C(1212153856),	// S2_storerhgp
    UINT64_C(2711619584),	// S2_storerhnew_io
    UINT64_C(2946500608),	// S2_storerhnew_pbr
    UINT64_C(2845837312),	// S2_storerhnew_pci
    UINT64_C(2845837314),	// S2_storerhnew_pcr
    UINT64_C(2879391744),	// S2_storerhnew_pi
    UINT64_C(2912946176),	// S2_storerhnew_pr
    UINT64_C(1218447360),	// S2_storerhnewgp
    UINT64_C(2709520384),	// S2_storeri_io
    UINT64_C(2944401408),	// S2_storeri_pbr
    UINT64_C(2843738112),	// S2_storeri_pci
    UINT64_C(2843738114),	// S2_storeri_pcr
    UINT64_C(2877292544),	// S2_storeri_pi
    UINT64_C(2910846976),	// S2_storeri_pr
    UINT64_C(1216348160),	// S2_storerigp
    UINT64_C(2711621632),	// S2_storerinew_io
    UINT64_C(2946502656),	// S2_storerinew_pbr
    UINT64_C(2845839360),	// S2_storerinew_pci
    UINT64_C(2845839362),	// S2_storerinew_pcr
    UINT64_C(2879393792),	// S2_storerinew_pi
    UINT64_C(2912948224),	// S2_storerinew_pr
    UINT64_C(1218449408),	// S2_storerinewgp
    UINT64_C(2694840320),	// S2_storew_locked
    UINT64_C(2694840328),	// S2_storew_rl_at_vi
    UINT64_C(2694840360),	// S2_storew_rl_st_vi
    UINT64_C(2357198848),	// S2_svsathb
    UINT64_C(2357198912),	// S2_svsathub
    UINT64_C(2264924160),	// S2_tableidxb
    UINT64_C(2277507072),	// S2_tableidxd
    UINT64_C(2269118464),	// S2_tableidxh
    UINT64_C(2273312768),	// S2_tableidxw
    UINT64_C(2361393216),	// S2_togglebit_i
    UINT64_C(3330277504),	// S2_togglebit_r
    UINT64_C(2231369728),	// S2_tstbit_i
    UINT64_C(3338665984),	// S2_tstbit_r
    UINT64_C(3221225472),	// S2_valignib
    UINT64_C(3254779904),	// S2_valignrb
    UINT64_C(3284140096),	// S2_vcnegh
    UINT64_C(3284140032),	// S2_vcrotate
    UINT64_C(3407880416),	// S2_vrcnegh
    UINT64_C(2290090112),	// S2_vrndpackwh
    UINT64_C(2290090176),	// S2_vrndpackwhs
    UINT64_C(2281701568),	// S2_vsathb
    UINT64_C(2147483872),	// S2_vsathb_nopack
    UINT64_C(2281701376),	// S2_vsathub
    UINT64_C(2147483776),	// S2_vsathub_nopack
    UINT64_C(2281701440),	// S2_vsatwh
    UINT64_C(2147483840),	// S2_vsatwh_nopack
    UINT64_C(2281701504),	// S2_vsatwuh
    UINT64_C(2147483808),	// S2_vsatwuh_nopack
    UINT64_C(2353004768),	// S2_vsplatrb
    UINT64_C(2218786880),	// S2_vsplatrh
    UINT64_C(3229614080),	// S2_vspliceib
    UINT64_C(3263168512),	// S2_vsplicerb
    UINT64_C(2214592512),	// S2_vsxtbh
    UINT64_C(2214592640),	// S2_vsxthw
    UINT64_C(2290090048),	// S2_vtrunehb
    UINT64_C(3246391360),	// S2_vtrunewh
    UINT64_C(2290089984),	// S2_vtrunohb
    UINT64_C(3246391424),	// S2_vtrunowh
    UINT64_C(2214592576),	// S2_vzxtbh
    UINT64_C(2214592704),	// S2_vzxthw
    UINT64_C(3674210304),	// S4_addaddi
    UINT64_C(3724541956),	// S4_addi_asl_ri
    UINT64_C(3724541972),	// S4_addi_lsr_ri
    UINT64_C(3724541952),	// S4_andi_asl_ri
    UINT64_C(3724541968),	// S4_andi_lsr_ri
    UINT64_C(2350907392),	// S4_clbaddi
    UINT64_C(2287992896),	// S4_clbpaddi
    UINT64_C(2287992832),	// S4_clbpnorm
    UINT64_C(2373976064),	// S4_extract
    UINT64_C(3372220480),	// S4_extract_rp
    UINT64_C(2315255808),	// S4_extractp
    UINT64_C(3250585728),	// S4_extractp_rp
    UINT64_C(3330277568),	// S4_lsli
    UINT64_C(2233466880),	// S4_ntstbit_i
    UINT64_C(3340763136),	// S4_ntstbit_r
    UINT64_C(3657433088),	// S4_or_andi
    UINT64_C(3661627392),	// S4_or_andix
    UINT64_C(3665821696),	// S4_or_ori
    UINT64_C(3724541954),	// S4_ori_asl_ri
    UINT64_C(3724541970),	// S4_ori_lsr_ri
    UINT64_C(3588227072),	// S4_parity
    UINT64_C(2936012932),	// S4_pstorerbf_abs
    UINT64_C(889192448),	// S4_pstorerbf_rr
    UINT64_C(2936021124),	// S4_pstorerbfnew_abs
    UINT64_C(1174405120),	// S4_pstorerbfnew_io
    UINT64_C(922746880),	// S4_pstorerbfnew_rr
    UINT64_C(2946498692),	// S4_pstorerbnewf_abs
    UINT64_C(899678208),	// S4_pstorerbnewf_rr
    UINT64_C(2946506884),	// S4_pstorerbnewfnew_abs
    UINT64_C(1184890880),	// S4_pstorerbnewfnew_io
    UINT64_C(933232640),	// S4_pstorerbnewfnew_rr
    UINT64_C(2946498688),	// S4_pstorerbnewt_abs
    UINT64_C(882900992),	// S4_pstorerbnewt_rr
    UINT64_C(2946506880),	// S4_pstorerbnewtnew_abs
    UINT64_C(1117782016),	// S4_pstorerbnewtnew_io
    UINT64_C(916455424),	// S4_pstorerbnewtnew_rr
    UINT64_C(2936012928),	// S4_pstorerbt_abs
    UINT64_C(872415232),	// S4_pstorerbt_rr
    UINT64_C(2936021120),	// S4_pstorerbtnew_abs
    UINT64_C(1107296256),	// S4_pstorerbtnew_io
    UINT64_C(905969664),	// S4_pstorerbtnew_rr
    UINT64_C(2948595844),	// S4_pstorerdf_abs
    UINT64_C(901775360),	// S4_pstorerdf_rr
    UINT64_C(2948604036),	// S4_pstorerdfnew_abs
    UINT64_C(1186988032),	// S4_pstorerdfnew_io
    UINT64_C(935329792),	// S4_pstorerdfnew_rr
    UINT64_C(2948595840),	// S4_pstorerdt_abs
    UINT64_C(884998144),	// S4_pstorerdt_rr
    UINT64_C(2948604032),	// S4_pstorerdtnew_abs
    UINT64_C(1119879168),	// S4_pstorerdtnew_io
    UINT64_C(918552576),	// S4_pstorerdtnew_rr
    UINT64_C(2942304388),	// S4_pstorerff_abs
    UINT64_C(895483904),	// S4_pstorerff_rr
    UINT64_C(2942312580),	// S4_pstorerffnew_abs
    UINT64_C(1180696576),	// S4_pstorerffnew_io
    UINT64_C(929038336),	// S4_pstorerffnew_rr
    UINT64_C(2942304384),	// S4_pstorerft_abs
    UINT64_C(878706688),	// S4_pstorerft_rr
    UINT64_C(2942312576),	// S4_pstorerftnew_abs
    UINT64_C(1113587712),	// S4_pstorerftnew_io
    UINT64_C(912261120),	// S4_pstorerftnew_rr
    UINT64_C(2940207236),	// S4_pstorerhf_abs
    UINT64_C(893386752),	// S4_pstorerhf_rr
    UINT64_C(2940215428),	// S4_pstorerhfnew_abs
    UINT64_C(1178599424),	// S4_pstorerhfnew_io
    UINT64_C(926941184),	// S4_pstorerhfnew_rr
    UINT64_C(2946500740),	// S4_pstorerhnewf_abs
    UINT64_C(899678216),	// S4_pstorerhnewf_rr
    UINT64_C(2946508932),	// S4_pstorerhnewfnew_abs
    UINT64_C(1184892928),	// S4_pstorerhnewfnew_io
    UINT64_C(933232648),	// S4_pstorerhnewfnew_rr
    UINT64_C(2946500736),	// S4_pstorerhnewt_abs
    UINT64_C(882901000),	// S4_pstorerhnewt_rr
    UINT64_C(2946508928),	// S4_pstorerhnewtnew_abs
    UINT64_C(1117784064),	// S4_pstorerhnewtnew_io
    UINT64_C(916455432),	// S4_pstorerhnewtnew_rr
    UINT64_C(2940207232),	// S4_pstorerht_abs
    UINT64_C(876609536),	// S4_pstorerht_rr
    UINT64_C(2940215424),	// S4_pstorerhtnew_abs
    UINT64_C(1111490560),	// S4_pstorerhtnew_io
    UINT64_C(910163968),	// S4_pstorerhtnew_rr
    UINT64_C(2944401540),	// S4_pstorerif_abs
    UINT64_C(897581056),	// S4_pstorerif_rr
    UINT64_C(2944409732),	// S4_pstorerifnew_abs
    UINT64_C(1182793728),	// S4_pstorerifnew_io
    UINT64_C(931135488),	// S4_pstorerifnew_rr
    UINT64_C(2946502788),	// S4_pstorerinewf_abs
    UINT64_C(899678224),	// S4_pstorerinewf_rr
    UINT64_C(2946510980),	// S4_pstorerinewfnew_abs
    UINT64_C(1184894976),	// S4_pstorerinewfnew_io
    UINT64_C(933232656),	// S4_pstorerinewfnew_rr
    UINT64_C(2946502784),	// S4_pstorerinewt_abs
    UINT64_C(882901008),	// S4_pstorerinewt_rr
    UINT64_C(2946510976),	// S4_pstorerinewtnew_abs
    UINT64_C(1117786112),	// S4_pstorerinewtnew_io
    UINT64_C(916455440),	// S4_pstorerinewtnew_rr
    UINT64_C(2944401536),	// S4_pstorerit_abs
    UINT64_C(880803840),	// S4_pstorerit_rr
    UINT64_C(2944409728),	// S4_pstoreritnew_abs
    UINT64_C(1115684864),	// S4_pstoreritnew_io
    UINT64_C(914358272),	// S4_pstoreritnew_rr
    UINT64_C(2699034624),	// S4_stored_locked
    UINT64_C(2699034632),	// S4_stored_rl_at_vi
    UINT64_C(2699034664),	// S4_stored_rl_st_vi
    UINT64_C(1006632960),	// S4_storeirb_io
    UINT64_C(947912704),	// S4_storeirbf_io
    UINT64_C(964689920),	// S4_storeirbfnew_io
    UINT64_C(939524096),	// S4_storeirbt_io
    UINT64_C(956301312),	// S4_storeirbtnew_io
    UINT64_C(1008730112),	// S4_storeirh_io
    UINT64_C(950009856),	// S4_storeirhf_io
    UINT64_C(966787072),	// S4_storeirhfnew_io
    UINT64_C(941621248),	// S4_storeirht_io
    UINT64_C(958398464),	// S4_storeirhtnew_io
    UINT64_C(1010827264),	// S4_storeiri_io
    UINT64_C(952107008),	// S4_storeirif_io
    UINT64_C(968884224),	// S4_storeirifnew_io
    UINT64_C(943718400),	// S4_storeirit_io
    UINT64_C(960495616),	// S4_storeiritnew_io
    UINT64_C(2868904064),	// S4_storerb_ap
    UINT64_C(989855744),	// S4_storerb_rr
    UINT64_C(2902458496),	// S4_storerb_ur
    UINT64_C(2879389824),	// S4_storerbnew_ap
    UINT64_C(1000341504),	// S4_storerbnew_rr
    UINT64_C(2912944256),	// S4_storerbnew_ur
    UINT64_C(2881486976),	// S4_storerd_ap
    UINT64_C(1002438656),	// S4_storerd_rr
    UINT64_C(2915041408),	// S4_storerd_ur
    UINT64_C(2875195520),	// S4_storerf_ap
    UINT64_C(996147200),	// S4_storerf_rr
    UINT64_C(2908749952),	// S4_storerf_ur
    UINT64_C(2873098368),	// S4_storerh_ap
    UINT64_C(994050048),	// S4_storerh_rr
    UINT64_C(2906652800),	// S4_storerh_ur
    UINT64_C(2879391872),	// S4_storerhnew_ap
    UINT64_C(1000341512),	// S4_storerhnew_rr
    UINT64_C(2912946304),	// S4_storerhnew_ur
    UINT64_C(2877292672),	// S4_storeri_ap
    UINT64_C(998244352),	// S4_storeri_rr
    UINT64_C(2910847104),	// S4_storeri_ur
    UINT64_C(2879393920),	// S4_storerinew_ap
    UINT64_C(1000341520),	// S4_storerinew_rr
    UINT64_C(2912948352),	// S4_storerinew_ur
    UINT64_C(3682598912),	// S4_subaddi
    UINT64_C(3724541958),	// S4_subi_asl_ri
    UINT64_C(3724541974),	// S4_subi_lsr_ri
    UINT64_C(3284140224),	// S4_vrcrotate
    UINT64_C(3416260608),	// S4_vrcrotate_acc
    UINT64_C(3242197120),	// S4_vxaddsubh
    UINT64_C(3250585600),	// S4_vxaddsubhr
    UINT64_C(3242196992),	// S4_vxaddsubw
    UINT64_C(3242197184),	// S4_vxsubaddh
    UINT64_C(3250585664),	// S4_vxsubaddhr
    UINT64_C(3242197056),	// S4_vxsubaddw
    UINT64_C(2287992960),	// S5_asrhub_rnd_sat
    UINT64_C(2287992992),	// S5_asrhub_sat
    UINT64_C(2287992928),	// S5_popcountp
    UINT64_C(2149580800),	// S5_vasrhrnd
    UINT64_C(2147483744),	// S6_rol_i_p
    UINT64_C(2181038304),	// S6_rol_i_p_acc
    UINT64_C(2185232480),	// S6_rol_i_p_and
    UINT64_C(2181038176),	// S6_rol_i_p_nac
    UINT64_C(2185232608),	// S6_rol_i_p_or
    UINT64_C(2189426784),	// S6_rol_i_p_xacc
    UINT64_C(2348810336),	// S6_rol_i_r
    UINT64_C(2382364896),	// S6_rol_i_r_acc
    UINT64_C(2386559072),	// S6_rol_i_r_and
    UINT64_C(2382364768),	// S6_rol_i_r_nac
    UINT64_C(2386559200),	// S6_rol_i_r_or
    UINT64_C(2390753376),	// S6_rol_i_r_xacc
    UINT64_C(2218786944),	// S6_vsplatrbp
    UINT64_C(3246391392),	// S6_vtrunehb_ppp
    UINT64_C(3246391456),	// S6_vtrunohb_ppp
    UINT64_C(0),	// SA1_addi
    UINT64_C(6144),	// SA1_addrx
    UINT64_C(3072),	// SA1_addsp
    UINT64_C(4608),	// SA1_and1
    UINT64_C(6768),	// SA1_clrf
    UINT64_C(6736),	// SA1_clrfnew
    UINT64_C(6752),	// SA1_clrt
    UINT64_C(6720),	// SA1_clrtnew
    UINT64_C(6400),	// SA1_cmpeqi
    UINT64_C(7168),	// SA1_combine0i
    UINT64_C(7176),	// SA1_combine1i
    UINT64_C(7184),	// SA1_combine2i
    UINT64_C(7192),	// SA1_combine3i
    UINT64_C(7432),	// SA1_combinerz
    UINT64_C(7424),	// SA1_combinezr
    UINT64_C(4864),	// SA1_dec
    UINT64_C(4352),	// SA1_inc
    UINT64_C(2048),	// SA1_seti
    UINT64_C(6656),	// SA1_setin1
    UINT64_C(5376),	// SA1_sxtb
    UINT64_C(5120),	// SA1_sxth
    UINT64_C(4096),	// SA1_tfr
    UINT64_C(5888),	// SA1_zxtb
    UINT64_C(5632),	// SA1_zxth
    UINT64_C(1509949440),	// SAVE_REGISTERS_CALL_V4
    UINT64_C(1509949440),	// SAVE_REGISTERS_CALL_V4STK
    UINT64_C(1509949440),	// SAVE_REGISTERS_CALL_V4STK_EXT
    UINT64_C(1509949440),	// SAVE_REGISTERS_CALL_V4STK_EXT_PIC
    UINT64_C(1509949440),	// SAVE_REGISTERS_CALL_V4STK_PIC
    UINT64_C(1509949440),	// SAVE_REGISTERS_CALL_V4_EXT
    UINT64_C(1509949440),	// SAVE_REGISTERS_CALL_V4_EXT_PIC
    UINT64_C(1509949440),	// SAVE_REGISTERS_CALL_V4_PIC
    UINT64_C(0),	// SL1_loadri_io
    UINT64_C(4096),	// SL1_loadrub_io
    UINT64_C(7936),	// SL2_deallocframe
    UINT64_C(8128),	// SL2_jumpr31
    UINT64_C(8133),	// SL2_jumpr31_f
    UINT64_C(8135),	// SL2_jumpr31_fnew
    UINT64_C(8132),	// SL2_jumpr31_t
    UINT64_C(8134),	// SL2_jumpr31_tnew
    UINT64_C(4096),	// SL2_loadrb_io
    UINT64_C(7680),	// SL2_loadrd_sp
    UINT64_C(0),	// SL2_loadrh_io
    UINT64_C(7168),	// SL2_loadri_sp
    UINT64_C(2048),	// SL2_loadruh_io
    UINT64_C(8000),	// SL2_return
    UINT64_C(8005),	// SL2_return_f
    UINT64_C(8007),	// SL2_return_fnew
    UINT64_C(8004),	// SL2_return_t
    UINT64_C(8006),	// SL2_return_tnew
    UINT64_C(4096),	// SS1_storeb_io
    UINT64_C(0),	// SS1_storew_io
    UINT64_C(7168),	// SS2_allocframe
    UINT64_C(4608),	// SS2_storebi0
    UINT64_C(4864),	// SS2_storebi1
    UINT64_C(2560),	// SS2_stored_sp
    UINT64_C(0),	// SS2_storeh_io
    UINT64_C(2048),	// SS2_storew_sp
    UINT64_C(4096),	// SS2_storewi0
    UINT64_C(4352),	// SS2_storewi1
    UINT64_C(0),	// TFRI64_V2_ext
    UINT64_C(0),	// TFRI64_V4
    UINT64_C(2449473568),	// V6_extractw
    UINT64_C(432013536),	// V6_get_qfext
    UINT64_C(432013504),	// V6_get_qfext_oracc
    UINT64_C(432013376),	// V6_lvsplatb
    UINT64_C(432013344),	// V6_lvsplath
    UINT64_C(429916192),	// V6_lvsplatw
    UINT64_C(503513088),	// V6_pred_and
    UINT64_C(503513108),	// V6_pred_and_n
    UINT64_C(503513096),	// V6_pred_not
    UINT64_C(503513092),	// V6_pred_or
    UINT64_C(503513104),	// V6_pred_or_n
    UINT64_C(429916228),	// V6_pred_scalar2
    UINT64_C(429916236),	// V6_pred_scalar2v2
    UINT64_C(503513100),	// V6_pred_xor
    UINT64_C(432013408),	// V6_set_qfext
    UINT64_C(503513112),	// V6_shuffeqh
    UINT64_C(503513116),	// V6_shuffeqw
    UINT64_C(524296320),	// V6_v6mpyhubs10
    UINT64_C(522199168),	// V6_v6mpyhubs10_vxx
    UINT64_C(524296192),	// V6_v6mpyvubs10
    UINT64_C(522199040),	// V6_v6mpyvubs10_vxx
    UINT64_C(671088864),	// V6_vL32Ub_ai
    UINT64_C(687866080),	// V6_vL32Ub_pi
    UINT64_C(721420512),	// V6_vL32Ub_ppu
    UINT64_C(671088640),	// V6_vL32b_ai
    UINT64_C(671088672),	// V6_vL32b_cur_ai
    UINT64_C(679477408),	// V6_vL32b_cur_npred_ai
    UINT64_C(696254624),	// V6_vL32b_cur_npred_pi
    UINT64_C(729809056),	// V6_vL32b_cur_npred_ppu
    UINT64_C(687865888),	// V6_vL32b_cur_pi
    UINT64_C(721420320),	// V6_vL32b_cur_ppu
    UINT64_C(679477376),	// V6_vL32b_cur_pred_ai
    UINT64_C(696254592),	// V6_vL32b_cur_pred_pi
    UINT64_C(729809024),	// V6_vL32b_cur_pred_ppu
    UINT64_C(679477344),	// V6_vL32b_npred_ai
    UINT64_C(696254560),	// V6_vL32b_npred_pi
    UINT64_C(729808992),	// V6_vL32b_npred_ppu
    UINT64_C(675282944),	// V6_vL32b_nt_ai
    UINT64_C(675282976),	// V6_vL32b_nt_cur_ai
    UINT64_C(683671712),	// V6_vL32b_nt_cur_npred_ai
    UINT64_C(700448928),	// V6_vL32b_nt_cur_npred_pi
    UINT64_C(734003360),	// V6_vL32b_nt_cur_npred_ppu
    UINT64_C(692060192),	// V6_vL32b_nt_cur_pi
    UINT64_C(725614624),	// V6_vL32b_nt_cur_ppu
    UINT64_C(683671680),	// V6_vL32b_nt_cur_pred_ai
    UINT64_C(700448896),	// V6_vL32b_nt_cur_pred_pi
    UINT64_C(734003328),	// V6_vL32b_nt_cur_pred_ppu
    UINT64_C(683671648),	// V6_vL32b_nt_npred_ai
    UINT64_C(700448864),	// V6_vL32b_nt_npred_pi
    UINT64_C(734003296),	// V6_vL32b_nt_npred_ppu
    UINT64_C(692060160),	// V6_vL32b_nt_pi
    UINT64_C(725614592),	// V6_vL32b_nt_ppu
    UINT64_C(683671616),	// V6_vL32b_nt_pred_ai
    UINT64_C(700448832),	// V6_vL32b_nt_pred_pi
    UINT64_C(734003264),	// V6_vL32b_nt_pred_ppu
    UINT64_C(675283008),	// V6_vL32b_nt_tmp_ai
    UINT64_C(683671776),	// V6_vL32b_nt_tmp_npred_ai
    UINT64_C(700448992),	// V6_vL32b_nt_tmp_npred_pi
    UINT64_C(734003424),	// V6_vL32b_nt_tmp_npred_ppu
    UINT64_C(692060224),	// V6_vL32b_nt_tmp_pi
    UINT64_C(725614656),	// V6_vL32b_nt_tmp_ppu
    UINT64_C(683671744),	// V6_vL32b_nt_tmp_pred_ai
    UINT64_C(700448960),	// V6_vL32b_nt_tmp_pred_pi
    UINT64_C(734003392),	// V6_vL32b_nt_tmp_pred_ppu
    UINT64_C(687865856),	// V6_vL32b_pi
    UINT64_C(721420288),	// V6_vL32b_ppu
    UINT64_C(679477312),	// V6_vL32b_pred_ai
    UINT64_C(696254528),	// V6_vL32b_pred_pi
    UINT64_C(729808960),	// V6_vL32b_pred_ppu
    UINT64_C(671088704),	// V6_vL32b_tmp_ai
    UINT64_C(679477472),	// V6_vL32b_tmp_npred_ai
    UINT64_C(696254688),	// V6_vL32b_tmp_npred_pi
    UINT64_C(729809120),	// V6_vL32b_tmp_npred_ppu
    UINT64_C(687865920),	// V6_vL32b_tmp_pi
    UINT64_C(721420352),	// V6_vL32b_tmp_ppu
    UINT64_C(679477440),	// V6_vL32b_tmp_pred_ai
    UINT64_C(696254656),	// V6_vL32b_tmp_pred_pi
    UINT64_C(729809088),	// V6_vL32b_tmp_pred_ppu
    UINT64_C(673186016),	// V6_vS32Ub_ai
    UINT64_C(681574624),	// V6_vS32Ub_npred_ai
    UINT64_C(698351840),	// V6_vS32Ub_npred_pi
    UINT64_C(731906272),	// V6_vS32Ub_npred_ppu
    UINT64_C(689963232),	// V6_vS32Ub_pi
    UINT64_C(723517664),	// V6_vS32Ub_ppu
    UINT64_C(681574592),	// V6_vS32Ub_pred_ai
    UINT64_C(698351808),	// V6_vS32Ub_pred_pi
    UINT64_C(731906240),	// V6_vS32Ub_pred_ppu
    UINT64_C(673185792),	// V6_vS32b_ai
    UINT64_C(673185824),	// V6_vS32b_new_ai
    UINT64_C(681574504),	// V6_vS32b_new_npred_ai
    UINT64_C(698351720),	// V6_vS32b_new_npred_pi
    UINT64_C(731906152),	// V6_vS32b_new_npred_ppu
    UINT64_C(689963040),	// V6_vS32b_new_pi
    UINT64_C(723517472),	// V6_vS32b_new_ppu
    UINT64_C(681574464),	// V6_vS32b_new_pred_ai
    UINT64_C(698351680),	// V6_vS32b_new_pred_pi
    UINT64_C(731906112),	// V6_vS32b_new_pred_ppu
    UINT64_C(681574432),	// V6_vS32b_npred_ai
    UINT64_C(698351648),	// V6_vS32b_npred_pi
    UINT64_C(731906080),	// V6_vS32b_npred_ppu
    UINT64_C(679477280),	// V6_vS32b_nqpred_ai
    UINT64_C(696254496),	// V6_vS32b_nqpred_pi
    UINT64_C(729808928),	// V6_vS32b_nqpred_ppu
    UINT64_C(677380096),	// V6_vS32b_nt_ai
    UINT64_C(677380128),	// V6_vS32b_nt_new_ai
    UINT64_C(685768824),	// V6_vS32b_nt_new_npred_ai
    UINT64_C(702546040),	// V6_vS32b_nt_new_npred_pi
    UINT64_C(736100472),	// V6_vS32b_nt_new_npred_ppu
    UINT64_C(694157344),	// V6_vS32b_nt_new_pi
    UINT64_C(727711776),	// V6_vS32b_nt_new_ppu
    UINT64_C(685768784),	// V6_vS32b_nt_new_pred_ai
    UINT64_C(702546000),	// V6_vS32b_nt_new_pred_pi
    UINT64_C(736100432),	// V6_vS32b_nt_new_pred_ppu
    UINT64_C(685768736),	// V6_vS32b_nt_npred_ai
    UINT64_C(702545952),	// V6_vS32b_nt_npred_pi
    UINT64_C(736100384),	// V6_vS32b_nt_npred_ppu
    UINT64_C(683671584),	// V6_vS32b_nt_nqpred_ai
    UINT64_C(700448800),	// V6_vS32b_nt_nqpred_pi
    UINT64_C(734003232),	// V6_vS32b_nt_nqpred_ppu
    UINT64_C(694157312),	// V6_vS32b_nt_pi
    UINT64_C(727711744),	// V6_vS32b_nt_ppu
    UINT64_C(685768704),	// V6_vS32b_nt_pred_ai
    UINT64_C(702545920),	// V6_vS32b_nt_pred_pi
    UINT64_C(736100352),	// V6_vS32b_nt_pred_ppu
    UINT64_C(683671552),	// V6_vS32b_nt_qpred_ai
    UINT64_C(700448768),	// V6_vS32b_nt_qpred_pi
    UINT64_C(734003200),	// V6_vS32b_nt_qpred_ppu
    UINT64_C(689963008),	// V6_vS32b_pi
    UINT64_C(723517440),	// V6_vS32b_ppu
    UINT64_C(681574400),	// V6_vS32b_pred_ai
    UINT64_C(698351616),	// V6_vS32b_pred_pi
    UINT64_C(731906048),	// V6_vS32b_pred_ppu
    UINT64_C(679477248),	// V6_vS32b_qpred_ai
    UINT64_C(696254464),	// V6_vS32b_qpred_pi
    UINT64_C(729808896),	// V6_vS32b_qpred_ppu
    UINT64_C(673185832),	// V6_vS32b_srls_ai
    UINT64_C(689963048),	// V6_vS32b_srls_pi
    UINT64_C(723517480),	// V6_vS32b_srls_ppu
    UINT64_C(476455104),	// V6_vabs_f8
    UINT64_C(503718016),	// V6_vabs_hf
    UINT64_C(504242368),	// V6_vabs_qf16_hf
    UINT64_C(504242400),	// V6_vabs_qf16_qf16
    UINT64_C(504242336),	// V6_vabs_qf32_qf32
    UINT64_C(504242304),	// V6_vabs_qf32_sf
    UINT64_C(503718048),	// V6_vabs_sf
    UINT64_C(503382144),	// V6_vabsb
    UINT64_C(503382176),	// V6_vabsb_sat
    UINT64_C(482344992),	// V6_vabsdiffh
    UINT64_C(482344960),	// V6_vabsdiffub
    UINT64_C(482345024),	// V6_vabsdiffuh
    UINT64_C(482345056),	// V6_vabsdiffw
    UINT64_C(503316480),	// V6_vabsh
    UINT64_C(503316512),	// V6_vabsh_sat
    UINT64_C(503316544),	// V6_vabsw
    UINT64_C(503316576),	// V6_vabsw_sat
    UINT64_C(526393440),	// V6_vadd_hf
    UINT64_C(528482432),	// V6_vadd_hf_f8
    UINT64_C(530587872),	// V6_vadd_hf_hf
    UINT64_C(526393408),	// V6_vadd_qf16
    UINT64_C(526393472),	// V6_vadd_qf16_mix
    UINT64_C(530587648),	// V6_vadd_qf32
    UINT64_C(530587712),	// V6_vadd_qf32_mix
    UINT64_C(530587680),	// V6_vadd_sf
    UINT64_C(490741952),	// V6_vadd_sf_bf
    UINT64_C(528490624),	// V6_vadd_sf_hf
    UINT64_C(528490688),	// V6_vadd_sf_sf
    UINT64_C(530579648),	// V6_vaddb
    UINT64_C(476053632),	// V6_vaddb_dv
    UINT64_C(503390304),	// V6_vaddbnq
    UINT64_C(503390208),	// V6_vaddbq
    UINT64_C(520093696),	// V6_vaddbsat
    UINT64_C(513802240),	// V6_vaddbsat_dv
    UINT64_C(480256000),	// V6_vaddcarry
    UINT64_C(497033216),	// V6_vaddcarryo
    UINT64_C(494936064),	// V6_vaddcarrysat
    UINT64_C(520101888),	// V6_vaddclbh
    UINT64_C(520101920),	// V6_vaddclbw
    UINT64_C(530579680),	// V6_vaddh
    UINT64_C(476053664),	// V6_vaddh_dv
    UINT64_C(503390336),	// V6_vaddhnq
    UINT64_C(503390240),	// V6_vaddhq
    UINT64_C(473956448),	// V6_vaddhsat
    UINT64_C(478150688),	// V6_vaddhsat_dv
    UINT64_C(480247936),	// V6_vaddhw
    UINT64_C(471867456),	// V6_vaddhw_acc
    UINT64_C(480247872),	// V6_vaddubh
    UINT64_C(473964704),	// V6_vaddubh_acc
    UINT64_C(473956384),	// V6_vaddubsat
    UINT64_C(476053728),	// V6_vaddubsat_dv
    UINT64_C(513802368),	// V6_vaddububb_sat
    UINT64_C(473956416),	// V6_vadduhsat
    UINT64_C(478150656),	// V6_vadduhsat_dv
    UINT64_C(480247904),	// V6_vadduhw
    UINT64_C(473964672),	// V6_vadduhw_acc
    UINT64_C(526385184),	// V6_vadduwsat
    UINT64_C(513802304),	// V6_vadduwsat_dv
    UINT64_C(473956352),	// V6_vaddw
    UINT64_C(476053696),	// V6_vaddw_dv
    UINT64_C(503390368),	// V6_vaddwnq
    UINT64_C(503390272),	// V6_vaddwq
    UINT64_C(473956480),	// V6_vaddwsat
    UINT64_C(478150720),	// V6_vaddwsat_dv
    UINT64_C(402653344),	// V6_valign4
    UINT64_C(452984832),	// V6_valignb
    UINT64_C(505421824),	// V6_valignbi
    UINT64_C(471859360),	// V6_vand
    UINT64_C(429917344),	// V6_vandnqrt
    UINT64_C(425731168),	// V6_vandnqrt_acc
    UINT64_C(429916320),	// V6_vandqrt
    UINT64_C(425730144),	// V6_vandqrt_acc
    UINT64_C(503521312),	// V6_vandvnqv
    UINT64_C(503521280),	// V6_vandvqv
    UINT64_C(429916232),	// V6_vandvrt
    UINT64_C(425730176),	// V6_vandvrt_acc
    UINT64_C(427819008),	// V6_vaslh
    UINT64_C(429924512),	// V6_vaslh_acc
    UINT64_C(530579616),	// V6_vaslhv
    UINT64_C(425722080),	// V6_vaslw
    UINT64_C(425730112),	// V6_vaslw_acc
    UINT64_C(530579584),	// V6_vaslwv
    UINT64_C(446701792),	// V6_vasr_into
    UINT64_C(425722048),	// V6_vasrh
    UINT64_C(427827424),	// V6_vasrh_acc
    UINT64_C(452993024),	// V6_vasrhbrndsat
    UINT64_C(402653184),	// V6_vasrhbsat
    UINT64_C(452985056),	// V6_vasrhubrndsat
    UINT64_C(452985024),	// V6_vasrhubsat
    UINT64_C(530579552),	// V6_vasrhv
    UINT64_C(402653408),	// V6_vasruhubrndsat
    UINT64_C(402661536),	// V6_vasruhubsat
    UINT64_C(402653216),	// V6_vasruwuhrndsat
    UINT64_C(402661504),	// V6_vasruwuhsat
    UINT64_C(486539360),	// V6_vasrvuhubrndsat
    UINT64_C(486539328),	// V6_vasrvuhubsat
    UINT64_C(486539296),	// V6_vasrvwuhrndsat
    UINT64_C(486539264),	// V6_vasrvwuhsat
    UINT64_C(425722016),	// V6_vasrw
    UINT64_C(425730208),	// V6_vasrw_acc
    UINT64_C(452984896),	// V6_vasrwh
    UINT64_C(452984960),	// V6_vasrwhrndsat
    UINT64_C(452984928),	// V6_vasrwhsat
    UINT64_C(402653248),	// V6_vasrwuhrndsat
    UINT64_C(452984992),	// V6_vasrwuhsat
    UINT64_C(530579456),	// V6_vasrwv
    UINT64_C(503521504),	// V6_vassign
    UINT64_C(503717920),	// V6_vassign_fp
    UINT64_C(503382208),	// V6_vassign_tmp
    UINT64_C(520102016),	// V6_vavgb
    UINT64_C(520102048),	// V6_vavgbrnd
    UINT64_C(482345152),	// V6_vavgh
    UINT64_C(484442272),	// V6_vavghrnd
    UINT64_C(482345088),	// V6_vavgub
    UINT64_C(484442208),	// V6_vavgubrnd
    UINT64_C(482345120),	// V6_vavguh
    UINT64_C(484442240),	// V6_vavguhrnd
    UINT64_C(520101952),	// V6_vavguw
    UINT64_C(520101984),	// V6_vavguwrnd
    UINT64_C(482345184),	// V6_vavgw
    UINT64_C(484442304),	// V6_vavgwrnd
    UINT64_C(442499072),	// V6_vccombine
    UINT64_C(503447776),	// V6_vcl0h
    UINT64_C(503447712),	// V6_vcl0w
    UINT64_C(436207616),	// V6_vcmov
    UINT64_C(524288224),	// V6_vcombine
    UINT64_C(513802464),	// V6_vcombine_tmp
    UINT64_C(503718112),	// V6_vconv_bf_qf32
    UINT64_C(504111328),	// V6_vconv_f8_qf16
    UINT64_C(503652416),	// V6_vconv_h_hf
    UINT64_C(503718080),	// V6_vconv_h_hf_rnd
    UINT64_C(503652480),	// V6_vconv_hf_h
    UINT64_C(503586912),	// V6_vconv_hf_qf16
    UINT64_C(503587008),	// V6_vconv_hf_qf32
    UINT64_C(504111264),	// V6_vconv_qf16_f8
    UINT64_C(504111232),	// V6_vconv_qf16_hf
    UINT64_C(504111296),	// V6_vconv_qf16_qf16
    UINT64_C(504176864),	// V6_vconv_qf32_qf32
    UINT64_C(504176832),	// V6_vconv_qf32_sf
    UINT64_C(503586816),	// V6_vconv_sf_qf32
    UINT64_C(503652448),	// V6_vconv_sf_w
    UINT64_C(503652384),	// V6_vconv_w_sf
    UINT64_C(448798912),	// V6_vcvt2_b_hf
    UINT64_C(517284032),	// V6_vcvt2_hf_b
    UINT64_C(517284064),	// V6_vcvt2_hf_ub
    UINT64_C(448798944),	// V6_vcvt2_ub_hf
    UINT64_C(532684992),	// V6_vcvt_b_hf
    UINT64_C(490741856),	// V6_vcvt_bf_sf
    UINT64_C(534782016),	// V6_vcvt_f8_hf
    UINT64_C(503717888),	// V6_vcvt_h_hf
    UINT64_C(503586880),	// V6_vcvt_hf_b
    UINT64_C(503652512),	// V6_vcvt_hf_f8
    UINT64_C(503587040),	// V6_vcvt_hf_h
    UINT64_C(526393376),	// V6_vcvt_hf_sf
    UINT64_C(503586848),	// V6_vcvt_hf_ub
    UINT64_C(503586976),	// V6_vcvt_hf_uh
    UINT64_C(503586944),	// V6_vcvt_sf_hf
    UINT64_C(532684960),	// V6_vcvt_ub_hf
    UINT64_C(503652352),	// V6_vcvt_uh_hf
    UINT64_C(434118720),	// V6_vdeal
    UINT64_C(503316704),	// V6_vdealb
    UINT64_C(522191072),	// V6_vdealb4w
    UINT64_C(503316672),	// V6_vdealh
    UINT64_C(452993152),	// V6_vdealvdd
    UINT64_C(522190880),	// V6_vdelta
    UINT64_C(530587840),	// V6_vdmpy_sf_hf
    UINT64_C(473964640),	// V6_vdmpy_sf_hf_acc
    UINT64_C(419430592),	// V6_vdmpybus
    UINT64_C(419438784),	// V6_vdmpybus_acc
    UINT64_C(419430624),	// V6_vdmpybus_dv
    UINT64_C(419438816),	// V6_vdmpybus_dv_acc
    UINT64_C(419430464),	// V6_vdmpyhb
    UINT64_C(419438688),	// V6_vdmpyhb_acc
    UINT64_C(421527680),	// V6_vdmpyhb_dv
    UINT64_C(421535872),	// V6_vdmpyhb_dv_acc
    UINT64_C(421527648),	// V6_vdmpyhisat
    UINT64_C(421535808),	// V6_vdmpyhisat_acc
    UINT64_C(421527616),	// V6_vdmpyhsat
    UINT64_C(421535840),	// V6_vdmpyhsat_acc
    UINT64_C(421527584),	// V6_vdmpyhsuisat
    UINT64_C(421535776),	// V6_vdmpyhsuisat_acc
    UINT64_C(421527552),	// V6_vdmpyhsusat
    UINT64_C(421535744),	// V6_vdmpyhsusat_acc
    UINT64_C(469762144),	// V6_vdmpyhvsat
    UINT64_C(469770336),	// V6_vdmpyhvsat_acc
    UINT64_C(419430560),	// V6_vdsaduh
    UINT64_C(425730048),	// V6_vdsaduh_acc
    UINT64_C(528482304),	// V6_veqb
    UINT64_C(478158848),	// V6_veqb_and
    UINT64_C(478158912),	// V6_veqb_or
    UINT64_C(478158976),	// V6_veqb_xor
    UINT64_C(528482308),	// V6_veqh
    UINT64_C(478158852),	// V6_veqh_and
    UINT64_C(478158916),	// V6_veqh_or
    UINT64_C(478158980),	// V6_veqh_xor
    UINT64_C(528482332),	// V6_veqhf
    UINT64_C(478158876),	// V6_veqhf_and
    UINT64_C(478158940),	// V6_veqhf_or
    UINT64_C(478159004),	// V6_veqhf_xor
    UINT64_C(528482316),	// V6_veqsf
    UINT64_C(478158860),	// V6_veqsf_and
    UINT64_C(478158924),	// V6_veqsf_or
    UINT64_C(478158988),	// V6_veqsf_xor
    UINT64_C(528482312),	// V6_veqw
    UINT64_C(478158856),	// V6_veqw_and
    UINT64_C(478158920),	// V6_veqw_or
    UINT64_C(478158984),	// V6_veqw_xor
    UINT64_C(476061856),	// V6_vfmax_f8
    UINT64_C(476061760),	// V6_vfmax_hf
    UINT64_C(476061792),	// V6_vfmax_sf
    UINT64_C(476061824),	// V6_vfmin_f8
    UINT64_C(476061696),	// V6_vfmin_hf
    UINT64_C(476061728),	// V6_vfmin_sf
    UINT64_C(476455136),	// V6_vfneg_f8
    UINT64_C(503717952),	// V6_vfneg_hf
    UINT64_C(503717984),	// V6_vfneg_sf
    UINT64_C(788529408),	// V6_vgathermh
    UINT64_C(788530432),	// V6_vgathermhq
    UINT64_C(788529664),	// V6_vgathermhw
    UINT64_C(788530688),	// V6_vgathermhwq
    UINT64_C(788529152),	// V6_vgathermw
    UINT64_C(788530176),	// V6_vgathermwq
    UINT64_C(528482320),	// V6_vgtb
    UINT64_C(478158864),	// V6_vgtb_and
    UINT64_C(478158928),	// V6_vgtb_or
    UINT64_C(478158992),	// V6_vgtb_xor
    UINT64_C(478158968),	// V6_vgtbf
    UINT64_C(478159056),	// V6_vgtbf_and
    UINT64_C(478158904),	// V6_vgtbf_or
    UINT64_C(478159088),	// V6_vgtbf_xor
    UINT64_C(528482324),	// V6_vgth
    UINT64_C(478158868),	// V6_vgth_and
    UINT64_C(478158932),	// V6_vgth_or
    UINT64_C(478158996),	// V6_vgth_xor
    UINT64_C(478158964),	// V6_vgthf
    UINT64_C(478159052),	// V6_vgthf_and
    UINT64_C(478158900),	// V6_vgthf_or
    UINT64_C(478159084),	// V6_vgthf_xor
    UINT64_C(478158960),	// V6_vgtsf
    UINT64_C(478159048),	// V6_vgtsf_and
    UINT64_C(478158896),	// V6_vgtsf_or
    UINT64_C(478159080),	// V6_vgtsf_xor
    UINT64_C(528482336),	// V6_vgtub
    UINT64_C(478158880),	// V6_vgtub_and
    UINT64_C(478158944),	// V6_vgtub_or
    UINT64_C(478159008),	// V6_vgtub_xor
    UINT64_C(528482340),	// V6_vgtuh
    UINT64_C(478158884),	// V6_vgtuh_and
    UINT64_C(478158948),	// V6_vgtuh_or
    UINT64_C(478159012),	// V6_vgtuh_xor
    UINT64_C(528482344),	// V6_vgtuw
    UINT64_C(478158888),	// V6_vgtuw_and
    UINT64_C(478158952),	// V6_vgtuw_or
    UINT64_C(478159016),	// V6_vgtuw_xor
    UINT64_C(528482328),	// V6_vgtw
    UINT64_C(478158872),	// V6_vgtw_and
    UINT64_C(478158936),	// V6_vgtw_or
    UINT64_C(478159000),	// V6_vgtw_xor
    UINT64_C(503324800),	// V6_vhist
    UINT64_C(503455872),	// V6_vhistq
    UINT64_C(504111200),	// V6_vilog2_hf
    UINT64_C(504111136),	// V6_vilog2_qf16
    UINT64_C(504111104),	// V6_vilog2_qf32
    UINT64_C(504111168),	// V6_vilog2_sf
    UINT64_C(429924384),	// V6_vinsertwr
    UINT64_C(452984864),	// V6_vlalignb
    UINT64_C(509616128),	// V6_vlalignbi
    UINT64_C(427819104),	// V6_vlsrb
    UINT64_C(427819072),	// V6_vlsrh
    UINT64_C(530579520),	// V6_vlsrhv
    UINT64_C(427819040),	// V6_vlsrw
    UINT64_C(530579488),	// V6_vlsrwv
    UINT64_C(425721984),	// V6_vlut4
    UINT64_C(452993056),	// V6_vlutvvb
    UINT64_C(402653280),	// V6_vlutvvb_nm
    UINT64_C(452993184),	// V6_vlutvvb_oracc
    UINT64_C(482353152),	// V6_vlutvvb_oracci
    UINT64_C(505413632),	// V6_vlutvvbi
    UINT64_C(452993216),	// V6_vlutvwh
    UINT64_C(402653312),	// V6_vlutvwh_nm
    UINT64_C(452993248),	// V6_vlutvwh_oracc
    UINT64_C(484450304),	// V6_vlutvwh_oracci
    UINT64_C(509607936),	// V6_vlutvwhi
    UINT64_C(490741984),	// V6_vmax_bf
    UINT64_C(532684896),	// V6_vmax_hf
    UINT64_C(532684832),	// V6_vmax_sf
    UINT64_C(522191008),	// V6_vmaxb
    UINT64_C(520093920),	// V6_vmaxh
    UINT64_C(520093856),	// V6_vmaxub
    UINT64_C(520093888),	// V6_vmaxuh
    UINT64_C(522190848),	// V6_vmaxw
    UINT64_C(520102112),	// V6_vmerge_qf
    UINT64_C(490741760),	// V6_vmin_bf
    UINT64_C(532684928),	// V6_vmin_hf
    UINT64_C(532684864),	// V6_vmin_sf
    UINT64_C(522190976),	// V6_vminb
    UINT64_C(520093792),	// V6_vminh
    UINT64_C(520093728),	// V6_vminub
    UINT64_C(520093760),	// V6_vminuh
    UINT64_C(520093824),	// V6_vminw
    UINT64_C(421527744),	// V6_vmpabus
    UINT64_C(421535936),	// V6_vmpabus_acc
    UINT64_C(471859296),	// V6_vmpabusv
    UINT64_C(425721952),	// V6_vmpabuu
    UINT64_C(429924480),	// V6_vmpabuu_acc
    UINT64_C(484442336),	// V6_vmpabuuv
    UINT64_C(421527776),	// V6_vmpahb
    UINT64_C(421535968),	// V6_vmpahb_acc
    UINT64_C(427827328),	// V6_vmpahhsat
    UINT64_C(427819168),	// V6_vmpauhb
    UINT64_C(427827264),	// V6_vmpauhb_acc
    UINT64_C(427827360),	// V6_vmpauhuhsat
    UINT64_C(427827392),	// V6_vmpsuhuhsat
    UINT64_C(528482496),	// V6_vmpy_hf_f8
    UINT64_C(528482528),	// V6_vmpy_hf_f8_acc
    UINT64_C(528490592),	// V6_vmpy_hf_hf
    UINT64_C(473964608),	// V6_vmpy_hf_hf_acc
    UINT64_C(534782048),	// V6_vmpy_qf16
    UINT64_C(534782080),	// V6_vmpy_qf16_hf
    UINT64_C(534782112),	// V6_vmpy_qf16_mix_hf
    UINT64_C(534781952),	// V6_vmpy_qf32
    UINT64_C(534782176),	// V6_vmpy_qf32_hf
    UINT64_C(528490496),	// V6_vmpy_qf32_mix_hf
    UINT64_C(534782144),	// V6_vmpy_qf32_qf16
    UINT64_C(534781984),	// V6_vmpy_qf32_sf
    UINT64_C(436215904),	// V6_vmpy_rt_hf
    UINT64_C(436215872),	// V6_vmpy_rt_qf16
    UINT64_C(436215840),	// V6_vmpy_rt_sf
    UINT64_C(490741888),	// V6_vmpy_sf_bf
    UINT64_C(486547456),	// V6_vmpy_sf_bf_acc
    UINT64_C(528490560),	// V6_vmpy_sf_hf
    UINT64_C(473964576),	// V6_vmpy_sf_hf_acc
    UINT64_C(528490528),	// V6_vmpy_sf_sf
    UINT64_C(421527712),	// V6_vmpybus
    UINT64_C(421535904),	// V6_vmpybus_acc
    UINT64_C(469762240),	// V6_vmpybusv
    UINT64_C(469770432),	// V6_vmpybusv_acc
    UINT64_C(469762176),	// V6_vmpybv
    UINT64_C(469770368),	// V6_vmpybv_acc
    UINT64_C(534773920),	// V6_vmpyewuh
    UINT64_C(513802432),	// V6_vmpyewuh_64
    UINT64_C(423624704),	// V6_vmpyh
    UINT64_C(429924544),	// V6_vmpyh_acc
    UINT64_C(423632896),	// V6_vmpyhsat_acc
    UINT64_C(423624768),	// V6_vmpyhsrs
    UINT64_C(423624736),	// V6_vmpyhss
    UINT64_C(471859264),	// V6_vmpyhus
    UINT64_C(471867424),	// V6_vmpyhus_acc
    UINT64_C(469762272),	// V6_vmpyhv
    UINT64_C(469770464),	// V6_vmpyhv_acc
    UINT64_C(471859232),	// V6_vmpyhvsrs
    UINT64_C(526385152),	// V6_vmpyieoh
    UINT64_C(473964544),	// V6_vmpyiewh_acc
    UINT64_C(532676608),	// V6_vmpyiewuh
    UINT64_C(471867552),	// V6_vmpyiewuh_acc
    UINT64_C(471859328),	// V6_vmpyih
    UINT64_C(471867520),	// V6_vmpyih_acc
    UINT64_C(425721856),	// V6_vmpyihb
    UINT64_C(425730080),	// V6_vmpyihb_acc
    UINT64_C(532676640),	// V6_vmpyiowh
    UINT64_C(429916160),	// V6_vmpyiwb
    UINT64_C(423632960),	// V6_vmpyiwb_acc
    UINT64_C(427819232),	// V6_vmpyiwh
    UINT64_C(423632992),	// V6_vmpyiwh_acc
    UINT64_C(427819200),	// V6_vmpyiwub
    UINT64_C(427827232),	// V6_vmpyiwub_acc
    UINT64_C(534773984),	// V6_vmpyowh
    UINT64_C(471867488),	// V6_vmpyowh_64_acc
    UINT64_C(524288000),	// V6_vmpyowh_rnd
    UINT64_C(471867616),	// V6_vmpyowh_rnd_sacc
    UINT64_C(471867584),	// V6_vmpyowh_sacc
    UINT64_C(432013312),	// V6_vmpyub
    UINT64_C(427827200),	// V6_vmpyub_acc
    UINT64_C(469762208),	// V6_vmpyubv
    UINT64_C(469770400),	// V6_vmpyubv_acc
    UINT64_C(423624800),	// V6_vmpyuh
    UINT64_C(423632928),	// V6_vmpyuh_acc
    UINT64_C(425721920),	// V6_vmpyuhe
    UINT64_C(427827296),	// V6_vmpyuhe_acc
    UINT64_C(471859200),	// V6_vmpyuhv
    UINT64_C(471867392),	// V6_vmpyuhv_acc
    UINT64_C(532685024),	// V6_vmpyuhvs
    UINT64_C(518004736),	// V6_vmux
    UINT64_C(520102080),	// V6_vnavgb
    UINT64_C(484442144),	// V6_vnavgh
    UINT64_C(484442112),	// V6_vnavgub
    UINT64_C(484442176),	// V6_vnavgw
    UINT64_C(440401920),	// V6_vnccombine
    UINT64_C(438304768),	// V6_vncmov
    UINT64_C(504242240),	// V6_vneg_qf16_hf
    UINT64_C(504242272),	// V6_vneg_qf16_qf16
    UINT64_C(504242208),	// V6_vneg_qf32_qf32
    UINT64_C(504242176),	// V6_vneg_qf32_sf
    UINT64_C(503513248),	// V6_vnormamth
    UINT64_C(503513216),	// V6_vnormamtw
    UINT64_C(503316608),	// V6_vnot
    UINT64_C(471859392),	// V6_vor
    UINT64_C(532676672),	// V6_vpackeb
    UINT64_C(532676704),	// V6_vpackeh
    UINT64_C(532676800),	// V6_vpackhb_sat
    UINT64_C(532676768),	// V6_vpackhub_sat
    UINT64_C(534773792),	// V6_vpackob
    UINT64_C(534773824),	// V6_vpackoh
    UINT64_C(534773760),	// V6_vpackwh_sat
    UINT64_C(532676832),	// V6_vpackwuh_sat
    UINT64_C(503447744),	// V6_vpopcounth
    UINT64_C(503521344),	// V6_vprefixqb
    UINT64_C(503521600),	// V6_vprefixqh
    UINT64_C(503521856),	// V6_vprefixqw
    UINT64_C(522190944),	// V6_vrdelta
    UINT64_C(432013472),	// V6_vrmpybub_rtt
    UINT64_C(429924352),	// V6_vrmpybub_rtt_acc
    UINT64_C(419430528),	// V6_vrmpybus
    UINT64_C(419438752),	// V6_vrmpybus_acc
    UINT64_C(423624832),	// V6_vrmpybusi
    UINT64_C(423633024),	// V6_vrmpybusi_acc
    UINT64_C(469762112),	// V6_vrmpybusv
    UINT64_C(469770304),	// V6_vrmpybusv_acc
    UINT64_C(469762080),	// V6_vrmpybv
    UINT64_C(469770272),	// V6_vrmpybv_acc
    UINT64_C(419430496),	// V6_vrmpyub
    UINT64_C(419438720),	// V6_vrmpyub_acc
    UINT64_C(432013440),	// V6_vrmpyub_rtt
    UINT64_C(429924576),	// V6_vrmpyub_rtt_acc
    UINT64_C(429916352),	// V6_vrmpyubi
    UINT64_C(425730240),	// V6_vrmpyubi_acc
    UINT64_C(469762048),	// V6_vrmpyubv
    UINT64_C(469770240),	// V6_vrmpyubv_acc
    UINT64_C(434634752),	// V6_vrmpyzbb_rt
    UINT64_C(432021568),	// V6_vrmpyzbb_rt_acc
    UINT64_C(434110464),	// V6_vrmpyzbb_rx
    UINT64_C(432545856),	// V6_vrmpyzbb_rx_acc
    UINT64_C(435683392),	// V6_vrmpyzbub_rt
    UINT64_C(433070112),	// V6_vrmpyzbub_rt_acc
    UINT64_C(435159104),	// V6_vrmpyzbub_rx
    UINT64_C(433594400),	// V6_vrmpyzbub_rx_acc
    UINT64_C(434634784),	// V6_vrmpyzcb_rt
    UINT64_C(432021600),	// V6_vrmpyzcb_rt_acc
    UINT64_C(434110496),	// V6_vrmpyzcb_rx
    UINT64_C(432545888),	// V6_vrmpyzcb_rx_acc
    UINT64_C(434634816),	// V6_vrmpyzcbs_rt
    UINT64_C(432021536),	// V6_vrmpyzcbs_rt_acc
    UINT64_C(434110528),	// V6_vrmpyzcbs_rx
    UINT64_C(432545824),	// V6_vrmpyzcbs_rx_acc
    UINT64_C(435683328),	// V6_vrmpyznb_rt
    UINT64_C(433070144),	// V6_vrmpyznb_rt_acc
    UINT64_C(435159040),	// V6_vrmpyznb_rx
    UINT64_C(433594432),	// V6_vrmpyznb_rx_acc
    UINT64_C(425721888),	// V6_vror
    UINT64_C(444604640),	// V6_vrotr
    UINT64_C(526385344),	// V6_vroundhb
    UINT64_C(526385376),	// V6_vroundhub
    UINT64_C(534773856),	// V6_vrounduhub
    UINT64_C(534773888),	// V6_vrounduwuh
    UINT64_C(526385280),	// V6_vroundwh
    UINT64_C(526385312),	// V6_vroundwuh
    UINT64_C(423624896),	// V6_vrsadubi
    UINT64_C(423633088),	// V6_vrsadubi_acc
    UINT64_C(494936288),	// V6_vsatdw
    UINT64_C(526385216),	// V6_vsathub
    UINT64_C(522191040),	// V6_vsatuwuh
    UINT64_C(526385248),	// V6_vsatwh
    UINT64_C(503447648),	// V6_vsb
    UINT64_C(790626336),	// V6_vscattermh
    UINT64_C(790626464),	// V6_vscattermh_add
    UINT64_C(796917888),	// V6_vscattermhq
    UINT64_C(790626368),	// V6_vscattermhw
    UINT64_C(790626496),	// V6_vscattermhw_add
    UINT64_C(799014912),	// V6_vscattermhwq
    UINT64_C(790626304),	// V6_vscattermw
    UINT64_C(790626432),	// V6_vscattermw_add
    UINT64_C(796917760),	// V6_vscattermwq
    UINT64_C(503447680),	// V6_vsh
    UINT64_C(524288096),	// V6_vshufeh
    UINT64_C(434118688),	// V6_vshuff
    UINT64_C(503447552),	// V6_vshuffb
    UINT64_C(524288032),	// V6_vshuffeb
    UINT64_C(503382240),	// V6_vshuffh
    UINT64_C(524288064),	// V6_vshuffob
    UINT64_C(452993120),	// V6_vshuffvdd
    UINT64_C(524288192),	// V6_vshufoeb
    UINT64_C(524288160),	// V6_vshufoeh
    UINT64_C(524288128),	// V6_vshufoh
    UINT64_C(526393536),	// V6_vsub_hf
    UINT64_C(528482464),	// V6_vsub_hf_f8
    UINT64_C(526393344),	// V6_vsub_hf_hf
    UINT64_C(436215936),	// V6_vsub_hf_mix
    UINT64_C(526393504),	// V6_vsub_qf16
    UINT64_C(526393568),	// V6_vsub_qf16_mix
    UINT64_C(530587744),	// V6_vsub_qf32
    UINT64_C(530587808),	// V6_vsub_qf32_mix
    UINT64_C(530587776),	// V6_vsub_sf
    UINT64_C(490741920),	// V6_vsub_sf_bf
    UINT64_C(528490656),	// V6_vsub_sf_hf
    UINT64_C(436215808),	// V6_vsub_sf_mix
    UINT64_C(528490720),	// V6_vsub_sf_sf
    UINT64_C(473956512),	// V6_vsubb
    UINT64_C(478150752),	// V6_vsubb_dv
    UINT64_C(503455776),	// V6_vsubbnq
    UINT64_C(503390400),	// V6_vsubbq
    UINT64_C(522190912),	// V6_vsubbsat
    UINT64_C(513802272),	// V6_vsubbsat_dv
    UINT64_C(480256128),	// V6_vsubcarry
    UINT64_C(497033344),	// V6_vsubcarryo
    UINT64_C(473956544),	// V6_vsubh
    UINT64_C(478150784),	// V6_vsubh_dv
    UINT64_C(503455808),	// V6_vsubhnq
    UINT64_C(503390432),	// V6_vsubhq
    UINT64_C(476053568),	// V6_vsubhsat
    UINT64_C(480247808),	// V6_vsubhsat_dv
    UINT64_C(480248032),	// V6_vsubhw
    UINT64_C(480247968),	// V6_vsububh
    UINT64_C(476053504),	// V6_vsububsat
    UINT64_C(478150848),	// V6_vsububsat_dv
    UINT64_C(513802400),	// V6_vsubububb_sat
    UINT64_C(476053536),	// V6_vsubuhsat
    UINT64_C(478150880),	// V6_vsubuhsat_dv
    UINT64_C(480248000),	// V6_vsubuhw
    UINT64_C(532676736),	// V6_vsubuwsat
    UINT64_C(513802336),	// V6_vsubuwsat_dv
    UINT64_C(473956576),	// V6_vsubw
    UINT64_C(478150816),	// V6_vsubw_dv
    UINT64_C(503455840),	// V6_vsubwnq
    UINT64_C(503455744),	// V6_vsubwq
    UINT64_C(476053600),	// V6_vsubwsat
    UINT64_C(480247840),	// V6_vsubwsat_dv
    UINT64_C(513810432),	// V6_vswap
    UINT64_C(419430400),	// V6_vtmpyb
    UINT64_C(419438592),	// V6_vtmpyb_acc
    UINT64_C(419430432),	// V6_vtmpybus
    UINT64_C(419438624),	// V6_vtmpybus_acc
    UINT64_C(429916288),	// V6_vtmpyhb
    UINT64_C(419438656),	// V6_vtmpyhb_acc
    UINT64_C(503382080),	// V6_vunpackb
    UINT64_C(503382112),	// V6_vunpackh
    UINT64_C(503324672),	// V6_vunpackob
    UINT64_C(503324704),	// V6_vunpackoh
    UINT64_C(503382016),	// V6_vunpackub
    UINT64_C(503382048),	// V6_vunpackuh
    UINT64_C(503325824),	// V6_vwhist128
    UINT64_C(503326336),	// V6_vwhist128m
    UINT64_C(503456896),	// V6_vwhist128q
    UINT64_C(503457408),	// V6_vwhist128qm
    UINT64_C(503325312),	// V6_vwhist256
    UINT64_C(503325568),	// V6_vwhist256_sat
    UINT64_C(503456384),	// V6_vwhist256q
    UINT64_C(503456640),	// V6_vwhist256q_sat
    UINT64_C(471859424),	// V6_vxor
    UINT64_C(503447584),	// V6_vzb
    UINT64_C(503447616),	// V6_vzh
    UINT64_C(738197504),	// V6_zLd_ai
    UINT64_C(754974720),	// V6_zLd_pi
    UINT64_C(754974721),	// V6_zLd_ppu
    UINT64_C(746586112),	// V6_zLd_pred_ai
    UINT64_C(763363328),	// V6_zLd_pred_pi
    UINT64_C(763363329),	// V6_zLd_pred_ppu
    UINT64_C(429916448),	// V6_zextract
    UINT64_C(2818572288),	// Y2_barrier
    UINT64_C(1814036480),	// Y2_break
    UINT64_C(1677721696),	// Y2_ciad
    UINT64_C(1694498816),	// Y2_crswap0
    UINT64_C(1677721632),	// Y2_cswi
    UINT64_C(2684354560),	// Y2_dccleana
    UINT64_C(2720006144),	// Y2_dccleanidx
    UINT64_C(2688548864),	// Y2_dccleaninva
    UINT64_C(2724200448),	// Y2_dccleaninvidx
    UINT64_C(2483027968),	// Y2_dcfetchbo
    UINT64_C(2686451712),	// Y2_dcinva
    UINT64_C(2722103296),	// Y2_dcinvidx
    UINT64_C(2717908992),	// Y2_dckill
    UINT64_C(2753560576),	// Y2_dctagr
    UINT64_C(2751463424),	// Y2_dctagw
    UINT64_C(2696937472),	// Y2_dczeroa
    UINT64_C(1711276032),	// Y2_getimask
    UINT64_C(1717567488),	// Y2_iassignr
    UINT64_C(1677721664),	// Y2_iassignw
    UINT64_C(1436549120),	// Y2_icdatar
    UINT64_C(1438654464),	// Y2_icdataw
    UINT64_C(1455423488),	// Y2_icinva
    UINT64_C(1455425536),	// Y2_icinvidx
    UINT64_C(1455427584),	// Y2_ickill
    UINT64_C(1440743424),	// Y2_ictagr
    UINT64_C(1438646272),	// Y2_ictagw
    UINT64_C(1472200706),	// Y2_isync
    UINT64_C(1814036576),	// Y2_k0lock
    UINT64_C(1814036608),	// Y2_k0unlock
    UINT64_C(2824863744),	// Y2_l2cleaninvidx
    UINT64_C(2820669440),	// Y2_l2kill
    UINT64_C(1681915936),	// Y2_resume
    UINT64_C(1686110208),	// Y2_setimask
    UINT64_C(1686110240),	// Y2_setprio
    UINT64_C(1684013088),	// Y2_start
    UINT64_C(1684013056),	// Y2_stop
    UINT64_C(1677721600),	// Y2_swi
    UINT64_C(2822766592),	// Y2_syncht
    UINT64_C(1853882368),	// Y2_tfrscrr
    UINT64_C(1728053248),	// Y2_tfrsrcr
    UINT64_C(1814036512),	// Y2_tlblock
    UINT64_C(1820327936),	// Y2_tlbp
    UINT64_C(1818230784),	// Y2_tlbpp
    UINT64_C(1816133632),	// Y2_tlbr
    UINT64_C(1814036544),	// Y2_tlbunlock
    UINT64_C(1811939328),	// Y2_tlbw
    UINT64_C(1681915904),	// Y2_wait
    UINT64_C(1696595968),	// Y4_crswap1
    UINT64_C(1837105152),	// Y4_crswap10
    UINT64_C(2785017856),	// Y4_l2fetch
    UINT64_C(2757754880),	// Y4_l2tagr
    UINT64_C(2755657728),	// Y4_l2tagw
    UINT64_C(1684013120),	// Y4_nmi
    UINT64_C(1686110304),	// Y4_siad
    UINT64_C(1862270976),	// Y4_tfrscpp
    UINT64_C(1828716544),	// Y4_tfrspcp
    UINT64_C(1648361472),	// Y4_trace
    UINT64_C(1824522240),	// Y5_ctlbw
    UINT64_C(2787115008),	// Y5_l2cleanidx
    UINT64_C(2793406464),	// Y5_l2fetch
    UINT64_C(2820673536),	// Y5_l2gclean
    UINT64_C(2820675584),	// Y5_l2gcleaninv
    UINT64_C(2820671488),	// Y5_l2gunlock
    UINT64_C(2789212160),	// Y5_l2invidx
    UINT64_C(2699042816),	// Y5_l2locka
    UINT64_C(2791309312),	// Y5_l2unlocka
    UINT64_C(1822425088),	// Y5_tlbasidi
    UINT64_C(1826619392),	// Y5_tlboc
    UINT64_C(1648361504),	// Y6_diag
    UINT64_C(1648361536),	// Y6_diag0
    UINT64_C(1648361568),	// Y6_diag1
    UINT64_C(2785017920),	// Y6_dmlink
    UINT64_C(2818572384),	// Y6_dmpause
    UINT64_C(2818572352),	// Y6_dmpoll
    UINT64_C(2785017984),	// Y6_dmresume
    UINT64_C(2785017888),	// Y6_dmstart
    UINT64_C(2818572320),	// Y6_dmwait
    UINT64_C(2797600768),	// Y6_l2gcleaninvpa
    UINT64_C(2795503616),	// Y6_l2gcleanpa
    UINT64_C(3581935616),	// dep_A2_addsat
    UINT64_C(3581935744),	// dep_A2_subsat
    UINT64_C(3556769792),	// dep_S2_packhl
    UINT64_C(0),	// invalid_decode
  };
  constexpr unsigned FirstSupportedOpcode = 943;

  const unsigned opcode = MI.getOpcode();
  if (opcode < FirstSupportedOpcode)
    reportUnsupportedInst(MI);
  unsigned TableIndex = opcode - FirstSupportedOpcode;
  uint64_t Value = InstBits[TableIndex];
  uint64_t op = 0;
  (void)op;  // suppress warning
  switch (opcode) {
    case Hexagon::A2_nop:
    case Hexagon::CONST32:
    case Hexagon::CONST64:
    case Hexagon::DuplexIClass0:
    case Hexagon::DuplexIClass1:
    case Hexagon::DuplexIClass2:
    case Hexagon::DuplexIClass3:
    case Hexagon::DuplexIClass4:
    case Hexagon::DuplexIClass5:
    case Hexagon::DuplexIClass6:
    case Hexagon::DuplexIClass7:
    case Hexagon::DuplexIClass8:
    case Hexagon::DuplexIClass9:
    case Hexagon::DuplexIClassA:
    case Hexagon::DuplexIClassB:
    case Hexagon::DuplexIClassC:
    case Hexagon::DuplexIClassD:
    case Hexagon::DuplexIClassE:
    case Hexagon::DuplexIClassF:
    case Hexagon::J2_rte:
    case Hexagon::J2_unpause:
    case Hexagon::SL2_deallocframe:
    case Hexagon::SL2_jumpr31:
    case Hexagon::SL2_jumpr31_f:
    case Hexagon::SL2_jumpr31_fnew:
    case Hexagon::SL2_jumpr31_t:
    case Hexagon::SL2_jumpr31_tnew:
    case Hexagon::SL2_return:
    case Hexagon::SL2_return_f:
    case Hexagon::SL2_return_fnew:
    case Hexagon::SL2_return_t:
    case Hexagon::SL2_return_tnew:
    case Hexagon::TFRI64_V2_ext:
    case Hexagon::TFRI64_V4:
    case Hexagon::V6_vhist:
    case Hexagon::V6_vwhist128:
    case Hexagon::V6_vwhist256:
    case Hexagon::V6_vwhist256_sat:
    case Hexagon::Y2_barrier:
    case Hexagon::Y2_break:
    case Hexagon::Y2_dckill:
    case Hexagon::Y2_ickill:
    case Hexagon::Y2_isync:
    case Hexagon::Y2_k0lock:
    case Hexagon::Y2_k0unlock:
    case Hexagon::Y2_l2kill:
    case Hexagon::Y2_syncht:
    case Hexagon::Y2_tlblock:
    case Hexagon::Y2_tlbunlock:
    case Hexagon::Y5_l2gclean:
    case Hexagon::Y5_l2gcleaninv:
    case Hexagon::Y5_l2gunlock:
    case Hexagon::invalid_decode: {
      break;
    }
    case Hexagon::A2_tfrcrr: {
      // op: Cs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::A4_tfrcpp: {
      // op: Css32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::G4_tfrgcrr: {
      // op: Gs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::G4_tfrgcpp: {
      // op: Gss32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::J4_cmpeqi_f_jumpnv_nt:
    case Hexagon::J4_cmpeqi_f_jumpnv_t:
    case Hexagon::J4_cmpeqi_t_jumpnv_nt:
    case Hexagon::J4_cmpeqi_t_jumpnv_t:
    case Hexagon::J4_cmpgti_f_jumpnv_nt:
    case Hexagon::J4_cmpgti_f_jumpnv_t:
    case Hexagon::J4_cmpgti_t_jumpnv_nt:
    case Hexagon::J4_cmpgti_t_jumpnv_t:
    case Hexagon::J4_cmpgtui_f_jumpnv_nt:
    case Hexagon::J4_cmpgtui_f_jumpnv_t:
    case Hexagon::J4_cmpgtui_t_jumpnv_nt:
    case Hexagon::J4_cmpgtui_t_jumpnv_t: {
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x600) << 11;
      Value |= (op & 0x1fc) >> 1;
      // op: Ns8
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7) << 16;
      break;
    }
    case Hexagon::J4_cmpeqi_fp0_jump_nt:
    case Hexagon::J4_cmpeqi_fp0_jump_t:
    case Hexagon::J4_cmpeqi_fp1_jump_nt:
    case Hexagon::J4_cmpeqi_fp1_jump_t:
    case Hexagon::J4_cmpeqi_tp0_jump_nt:
    case Hexagon::J4_cmpeqi_tp0_jump_t:
    case Hexagon::J4_cmpeqi_tp1_jump_nt:
    case Hexagon::J4_cmpeqi_tp1_jump_t:
    case Hexagon::J4_cmpgti_fp0_jump_nt:
    case Hexagon::J4_cmpgti_fp0_jump_t:
    case Hexagon::J4_cmpgti_fp1_jump_nt:
    case Hexagon::J4_cmpgti_fp1_jump_t:
    case Hexagon::J4_cmpgti_tp0_jump_nt:
    case Hexagon::J4_cmpgti_tp0_jump_t:
    case Hexagon::J4_cmpgti_tp1_jump_nt:
    case Hexagon::J4_cmpgti_tp1_jump_t:
    case Hexagon::J4_cmpgtui_fp0_jump_nt:
    case Hexagon::J4_cmpgtui_fp0_jump_t:
    case Hexagon::J4_cmpgtui_fp1_jump_nt:
    case Hexagon::J4_cmpgtui_fp1_jump_t:
    case Hexagon::J4_cmpgtui_tp0_jump_nt:
    case Hexagon::J4_cmpgtui_tp0_jump_t:
    case Hexagon::J4_cmpgtui_tp1_jump_nt:
    case Hexagon::J4_cmpgtui_tp1_jump_t: {
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x600) << 11;
      Value |= (op & 0x1fc) >> 1;
      // op: Rs16
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 16;
      break;
    }
    case Hexagon::J4_jumpseti: {
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3f) << 8;
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x600) << 11;
      Value |= (op & 0x1fc) >> 1;
      // op: Rd16
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 16;
      break;
    }
    case Hexagon::S4_storerbnew_ap:
    case Hexagon::S4_storerhnew_ap:
    case Hexagon::S4_storerinew_ap: {
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3f);
      // op: Nt8
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: Re32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::S4_storerb_ap:
    case Hexagon::S4_storerf_ap:
    case Hexagon::S4_storerh_ap:
    case Hexagon::S4_storeri_ap: {
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3f);
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Re32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::S4_storerd_ap: {
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3f);
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Re32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::L4_loadbsw2_ap:
    case Hexagon::L4_loadbzw2_ap:
    case Hexagon::L4_loadrb_ap:
    case Hexagon::L4_loadrh_ap:
    case Hexagon::L4_loadri_ap:
    case Hexagon::L4_loadrub_ap:
    case Hexagon::L4_loadruh_ap: {
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3c) << 6;
      Value |= (op & 0x3) << 5;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Re32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::L4_loadbsw4_ap:
    case Hexagon::L4_loadbzw4_ap:
    case Hexagon::L4_loadrd_ap: {
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3c) << 6;
      Value |= (op & 0x3) << 5;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Re32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::L4_loadalignb_ap:
    case Hexagon::L4_loadalignh_ap: {
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x3c) << 6;
      Value |= (op & 0x3) << 5;
      // op: Ryy32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Re32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::V6_vwhist128m: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1) << 8;
      break;
    }
    case Hexagon::PS_storerhnewabs:
    case Hexagon::S2_storerhnewgp: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x18000) << 10;
      Value |= (op & 0x7c00) << 6;
      Value |= (op & 0x200) << 4;
      Value |= (op & 0x1fe) >> 1;
      // op: Nt8
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7) << 8;
      break;
    }
    case Hexagon::PS_storerfabs:
    case Hexagon::PS_storerhabs:
    case Hexagon::S2_storerfgp:
    case Hexagon::S2_storerhgp: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x18000) << 10;
      Value |= (op & 0x7c00) << 6;
      Value |= (op & 0x200) << 4;
      Value |= (op & 0x1fe) >> 1;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      break;
    }
    case Hexagon::J2_loop0i:
    case Hexagon::J2_loop1i:
    case Hexagon::J2_ploop1si:
    case Hexagon::J2_ploop2si:
    case Hexagon::J2_ploop3si: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f0) << 4;
      Value |= (op & 0xc) << 1;
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3e0) << 11;
      Value |= (op & 0x1c) << 3;
      Value |= (op & 0x3);
      break;
    }
    case Hexagon::J2_loop0r:
    case Hexagon::J2_loop1r:
    case Hexagon::J2_ploop1sr:
    case Hexagon::J2_ploop2sr:
    case Hexagon::J2_ploop3sr: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f0) << 4;
      Value |= (op & 0xc) << 1;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::SS2_stored_sp: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f8);
      // op: Rtt8
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7);
      break;
    }
    case Hexagon::J2_pause: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x300) << 8;
      Value |= (op & 0xf8) << 5;
      Value |= (op & 0x7) << 2;
      break;
    }
    case Hexagon::PS_storerinewabs:
    case Hexagon::S2_storerinewgp: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x30000) << 9;
      Value |= (op & 0xf800) << 5;
      Value |= (op & 0x400) << 3;
      Value |= (op & 0x3fc) >> 2;
      // op: Nt8
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7) << 8;
      break;
    }
    case Hexagon::PS_storeriabs:
    case Hexagon::S2_storerigp: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x30000) << 9;
      Value |= (op & 0xf800) << 5;
      Value |= (op & 0x400) << 3;
      Value |= (op & 0x3fc) >> 2;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      break;
    }
    case Hexagon::PS_storerdabs:
    case Hexagon::S2_storerdgp: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x60000) << 8;
      Value |= (op & 0x1f000) << 4;
      Value |= (op & 0x800) << 2;
      Value |= (op & 0x7f8) >> 3;
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      break;
    }
    case Hexagon::SS2_storew_sp: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7c) << 2;
      // op: Rt16
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf);
      break;
    }
    case Hexagon::PS_storerbnewabs:
    case Hexagon::S2_storerbnewgp: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xc000) << 11;
      Value |= (op & 0x3e00) << 7;
      Value |= (op & 0x100) << 5;
      Value |= (op & 0xff);
      // op: Nt8
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7) << 8;
      break;
    }
    case Hexagon::PS_storerbabs:
    case Hexagon::S2_storerbgp: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xc000) << 11;
      Value |= (op & 0x3e00) << 7;
      Value |= (op & 0x100) << 5;
      Value |= (op & 0xff);
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      break;
    }
    case Hexagon::SS2_allocframe: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf8) << 1;
      break;
    }
    case Hexagon::J2_trap0:
    case Hexagon::PS_trap1: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf8) << 5;
      Value |= (op & 0x7) << 2;
      break;
    }
    case Hexagon::J2_call:
    case Hexagon::J2_jump: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xff8000) << 1;
      Value |= (op & 0x7ffc) >> 1;
      break;
    }
    case Hexagon::A4_ext: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xfff00000) >> 4;
      Value |= (op & 0xfffc0) >> 6;
      break;
    }
    case Hexagon::V6_vwhist128qm: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1) << 8;
      // op: Qv4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3) << 22;
      break;
    }
    case Hexagon::S2_storerinew_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1800) << 14;
      Value |= (op & 0x400) << 3;
      Value |= (op & 0x3fc) >> 2;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Nt8
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x7) << 8;
      break;
    }
    case Hexagon::S2_storeri_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1800) << 14;
      Value |= (op & 0x400) << 3;
      Value |= (op & 0x3fc) >> 2;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      break;
    }
    case Hexagon::L2_loadrhgp:
    case Hexagon::L2_loadruhgp:
    case Hexagon::PS_loadrhabs:
    case Hexagon::PS_loadruhabs: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x18000) << 10;
      Value |= (op & 0x7c00) << 6;
      Value |= (op & 0x3fe) << 4;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::J2_callf:
    case Hexagon::J2_callt:
    case Hexagon::J2_jumpf:
    case Hexagon::J2_jumpfnew:
    case Hexagon::J2_jumpfnewpt:
    case Hexagon::J2_jumpfpt:
    case Hexagon::J2_jumpt:
    case Hexagon::J2_jumptnew:
    case Hexagon::J2_jumptnewpt:
    case Hexagon::J2_jumptpt: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x18000) << 7;
      Value |= (op & 0x7c00) << 6;
      Value |= (op & 0x200) << 4;
      Value |= (op & 0x1fc) >> 1;
      // op: Pu4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3) << 8;
      break;
    }
    case Hexagon::S2_mask: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x18) << 18;
      Value |= (op & 0x7) << 5;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S4_storerbnew_ur:
    case Hexagon::S4_storerhnew_ur:
    case Hexagon::S4_storerinew_ur: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x2) << 12;
      Value |= (op & 0x1) << 6;
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3f);
      // op: Ru32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Nt8
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x7) << 8;
      break;
    }
    case Hexagon::S4_storerb_ur:
    case Hexagon::S4_storerf_ur:
    case Hexagon::S4_storerh_ur:
    case Hexagon::S4_storeri_ur: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x2) << 12;
      Value |= (op & 0x1) << 6;
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3f);
      // op: Ru32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      break;
    }
    case Hexagon::S4_storerd_ur: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x2) << 12;
      Value |= (op & 0x1) << 6;
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3f);
      // op: Ru32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      break;
    }
    case Hexagon::F2_sfimm_n:
    case Hexagon::F2_sfimm_p: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x200) << 12;
      Value |= (op & 0x1ff) << 5;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::F2_dfimm_n:
    case Hexagon::F2_dfimm_p: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x200) << 12;
      Value |= (op & 0x1ff) << 5;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::A2_subri: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x200) << 12;
      Value |= (op & 0x1ff) << 5;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::SA1_combine0i:
    case Hexagon::SA1_combine1i:
    case Hexagon::SA1_combine2i:
    case Hexagon::SA1_combine3i: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 5;
      // op: Rdd8
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7);
      break;
    }
    case Hexagon::SA1_cmpeqi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3);
      // op: Rs16
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 4;
      break;
    }
    case Hexagon::S4_pstorerbnewf_abs:
    case Hexagon::S4_pstorerbnewfnew_abs:
    case Hexagon::S4_pstorerbnewt_abs:
    case Hexagon::S4_pstorerbnewtnew_abs:
    case Hexagon::S4_pstorerhnewf_abs:
    case Hexagon::S4_pstorerhnewfnew_abs:
    case Hexagon::S4_pstorerhnewt_abs:
    case Hexagon::S4_pstorerhnewtnew_abs:
    case Hexagon::S4_pstorerinewf_abs:
    case Hexagon::S4_pstorerinewfnew_abs:
    case Hexagon::S4_pstorerinewt_abs:
    case Hexagon::S4_pstorerinewtnew_abs: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x30) << 12;
      Value |= (op & 0xf) << 3;
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      // op: Nt8
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x7) << 8;
      break;
    }
    case Hexagon::S4_pstorerbf_abs:
    case Hexagon::S4_pstorerbfnew_abs:
    case Hexagon::S4_pstorerbt_abs:
    case Hexagon::S4_pstorerbtnew_abs:
    case Hexagon::S4_pstorerff_abs:
    case Hexagon::S4_pstorerffnew_abs:
    case Hexagon::S4_pstorerft_abs:
    case Hexagon::S4_pstorerftnew_abs:
    case Hexagon::S4_pstorerhf_abs:
    case Hexagon::S4_pstorerhfnew_abs:
    case Hexagon::S4_pstorerht_abs:
    case Hexagon::S4_pstorerhtnew_abs:
    case Hexagon::S4_pstorerif_abs:
    case Hexagon::S4_pstorerifnew_abs:
    case Hexagon::S4_pstorerit_abs:
    case Hexagon::S4_pstoreritnew_abs: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x30) << 12;
      Value |= (op & 0xf) << 3;
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      break;
    }
    case Hexagon::S4_pstorerdf_abs:
    case Hexagon::S4_pstorerdfnew_abs:
    case Hexagon::S4_pstorerdt_abs:
    case Hexagon::S4_pstorerdtnew_abs: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x30) << 12;
      Value |= (op & 0xf) << 3;
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      break;
    }
    case Hexagon::M4_mpyri_addi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x30) << 17;
      Value |= (op & 0x8) << 10;
      Value |= (op & 0x7) << 5;
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x20) << 18;
      Value |= (op & 0x1f);
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      break;
    }
    case Hexagon::M4_mpyrr_addi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x30) << 17;
      Value |= (op & 0x8) << 10;
      Value |= (op & 0x7) << 5;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S2_storerd_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3000) << 13;
      Value |= (op & 0x800) << 2;
      Value |= (op & 0x7f8) >> 3;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      break;
    }
    case Hexagon::L2_loadrigp:
    case Hexagon::PS_loadriabs: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x30000) << 9;
      Value |= (op & 0xf800) << 5;
      Value |= (op & 0x7fc) << 3;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::SS1_storew_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3c) << 6;
      // op: Rs16
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 4;
      // op: Rt16
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xf);
      break;
    }
    case Hexagon::SS2_storewi0:
    case Hexagon::SS2_storewi1: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3c) >> 2;
      // op: Rs16
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 4;
      break;
    }
    case Hexagon::S4_lsli: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3e) << 15;
      Value |= (op & 0x1) << 5;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::SA1_seti: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3f) << 4;
      // op: Rd16
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf);
      break;
    }
    case Hexagon::L4_iadd_memopb_io:
    case Hexagon::L4_iand_memopb_io:
    case Hexagon::L4_ior_memopb_io:
    case Hexagon::L4_isub_memopb_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3f) << 7;
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::S4_storeirb_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3f) << 7;
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x80) << 6;
      Value |= (op & 0x7f);
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::C4_addipc: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3f) << 7;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::L4_add_memopb_io:
    case Hexagon::L4_and_memopb_io:
    case Hexagon::L4_or_memopb_io:
    case Hexagon::L4_sub_memopb_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3f) << 7;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::Y2_dcfetchbo: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3ff8) >> 3;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::J2_jumprgtez:
    case Hexagon::J2_jumprgtezpt:
    case Hexagon::J2_jumprltez:
    case Hexagon::J2_jumprltezpt:
    case Hexagon::J2_jumprnz:
    case Hexagon::J2_jumprnzpt:
    case Hexagon::J2_jumprz:
    case Hexagon::J2_jumprzpt: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x4000) << 7;
      Value |= (op & 0x2000);
      Value |= (op & 0x1ffc) >> 1;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::J4_tstbit0_f_jumpnv_nt:
    case Hexagon::J4_tstbit0_f_jumpnv_t:
    case Hexagon::J4_tstbit0_t_jumpnv_nt:
    case Hexagon::J4_tstbit0_t_jumpnv_t: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x600) << 11;
      Value |= (op & 0x1fc) >> 1;
      // op: Ns8
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7) << 16;
      break;
    }
    case Hexagon::J4_tstbit0_fp0_jump_nt:
    case Hexagon::J4_tstbit0_fp0_jump_t:
    case Hexagon::J4_tstbit0_fp1_jump_nt:
    case Hexagon::J4_tstbit0_fp1_jump_t:
    case Hexagon::J4_tstbit0_tp0_jump_nt:
    case Hexagon::J4_tstbit0_tp0_jump_t:
    case Hexagon::J4_tstbit0_tp1_jump_nt:
    case Hexagon::J4_tstbit0_tp1_jump_t: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x600) << 11;
      Value |= (op & 0x1fc) >> 1;
      // op: Rs16
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 16;
      break;
    }
    case Hexagon::S2_storerbnew_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x600) << 16;
      Value |= (op & 0x100) << 5;
      Value |= (op & 0xff);
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Nt8
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x7) << 8;
      break;
    }
    case Hexagon::S2_storerb_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x600) << 16;
      Value |= (op & 0x100) << 5;
      Value |= (op & 0xff);
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      break;
    }
    case Hexagon::L2_loadrdgp:
    case Hexagon::PS_loadrdabs: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x60000) << 8;
      Value |= (op & 0x1f000) << 4;
      Value |= (op & 0xff8) << 2;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::SL2_loadri_sp: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7c) << 2;
      // op: Rd16
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf);
      break;
    }
    case Hexagon::L4_iadd_memoph_io:
    case Hexagon::L4_iand_memoph_io:
    case Hexagon::L4_ior_memoph_io:
    case Hexagon::L4_isub_memoph_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7e) << 6;
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::S4_storeirh_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7e) << 6;
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x80) << 6;
      Value |= (op & 0x7f);
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::L4_add_memoph_io:
    case Hexagon::L4_and_memoph_io:
    case Hexagon::L4_or_memoph_io:
    case Hexagon::L4_sub_memoph_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7e) << 6;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vS32b_srls_ai:
    case Hexagon::V6_zLd_ai: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x8) << 10;
      Value |= (op & 0x7) << 8;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::V6_vS32b_new_ai:
    case Hexagon::V6_vS32b_nt_new_ai: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x8) << 10;
      Value |= (op & 0x7) << 8;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Os8
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x7);
      break;
    }
    case Hexagon::V6_vS32Ub_ai:
    case Hexagon::V6_vS32b_ai:
    case Hexagon::V6_vS32b_nt_ai: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x8) << 10;
      Value |= (op & 0x7) << 8;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S2_storerhnew_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xc00) << 15;
      Value |= (op & 0x200) << 4;
      Value |= (op & 0x1fe) >> 1;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Nt8
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x7) << 8;
      break;
    }
    case Hexagon::S2_storerf_io:
    case Hexagon::S2_storerh_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xc00) << 15;
      Value |= (op & 0x200) << 4;
      Value |= (op & 0x1fe) >> 1;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      break;
    }
    case Hexagon::L2_loadrbgp:
    case Hexagon::L2_loadrubgp:
    case Hexagon::PS_loadrbabs:
    case Hexagon::PS_loadrubabs: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xc000) << 11;
      Value |= (op & 0x3e00) << 7;
      Value |= (op & 0x1ff) << 5;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::A2_tfrsi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xc000) << 8;
      Value |= (op & 0x3e00) << 7;
      Value |= (op & 0x1ff) << 5;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::SS2_storeh_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xe) << 7;
      // op: Rs16
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 4;
      // op: Rt16
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xf);
      break;
    }
    case Hexagon::S4_addi_asl_ri:
    case Hexagon::S4_addi_lsr_ri:
    case Hexagon::S4_andi_asl_ri:
    case Hexagon::S4_andi_lsr_ri:
    case Hexagon::S4_ori_asl_ri:
    case Hexagon::S4_ori_lsr_ri:
    case Hexagon::S4_subi_asl_ri:
    case Hexagon::S4_subi_lsr_ri: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xe0) << 16;
      Value |= (op & 0x10) << 9;
      Value |= (op & 0xe) << 4;
      Value |= (op & 0x1) << 3;
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::SS1_storeb_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 8;
      // op: Rs16
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 4;
      // op: Rt16
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xf);
      break;
    }
    case Hexagon::SS2_storebi0:
    case Hexagon::SS2_storebi1: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf);
      // op: Rs16
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 4;
      break;
    }
    case Hexagon::SL2_loadrd_sp: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf8);
      // op: Rdd8
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7);
      break;
    }
    case Hexagon::SA1_addsp: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xfc) << 2;
      // op: Rd16
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf);
      break;
    }
    case Hexagon::L4_iadd_memopw_io:
    case Hexagon::L4_iand_memopw_io:
    case Hexagon::L4_ior_memopw_io:
    case Hexagon::L4_isub_memopw_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xfc) << 5;
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::S4_storeiri_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xfc) << 5;
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x80) << 6;
      Value |= (op & 0x7f);
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::L4_add_memopw_io:
    case Hexagon::L4_and_memopw_io:
    case Hexagon::L4_or_memopw_io:
    case Hexagon::L4_sub_memopw_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xfc) << 5;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::A4_combineii: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xff) << 5;
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3e) << 15;
      Value |= (op & 0x1) << 13;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::A2_combineii: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xff) << 5;
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xfe) << 15;
      Value |= (op & 0x1) << 13;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::A4_combineir: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xff) << 5;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S2_pstorerdf_io:
    case Hexagon::S2_pstorerdt_io:
    case Hexagon::S4_pstorerdfnew_io:
    case Hexagon::S4_pstorerdtnew_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x100) << 5;
      Value |= (op & 0xf8);
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      break;
    }
    case Hexagon::L2_loadri_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1800) << 14;
      Value |= (op & 0x7fc) << 3;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::L2_loadbsw4_io:
    case Hexagon::L2_loadbzw4_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1800) << 14;
      Value |= (op & 0x7fc) << 3;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S2_storerhnew_pci: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1e) << 2;
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Nt8
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::S2_storerf_pci:
    case Hexagon::S2_storerh_pci: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1e) << 2;
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::S2_storerhnew_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1e) << 2;
      // op: Nt8
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::S2_storerf_pi:
    case Hexagon::S2_storerh_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1e) << 2;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::F2_dfclass: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 5;
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Pd4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      break;
    }
    case Hexagon::S2_extractu:
    case Hexagon::S4_extract: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x18) << 18;
      Value |= (op & 0x7) << 5;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::F2_sfclass:
    case Hexagon::S2_tstbit_i:
    case Hexagon::S4_ntstbit_i: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Pd4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      break;
    }
    case Hexagon::A4_cround_ri:
    case Hexagon::A4_round_ri:
    case Hexagon::A4_round_ri_sat:
    case Hexagon::A7_clip:
    case Hexagon::S2_asl_i_r:
    case Hexagon::S2_asl_i_r_sat:
    case Hexagon::S2_asr_i_r:
    case Hexagon::S2_asr_i_r_rnd:
    case Hexagon::S2_clrbit_i:
    case Hexagon::S2_lsr_i_r:
    case Hexagon::S2_setbit_i:
    case Hexagon::S2_togglebit_i:
    case Hexagon::S6_rol_i_r: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::A4_bitspliti: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S2_asr_i_svw_trun: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::A7_vclip:
    case Hexagon::S2_asl_i_vw:
    case Hexagon::S2_asr_i_vw:
    case Hexagon::S2_lsr_i_vw: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::C2_cmpgtui:
    case Hexagon::C4_cmplteui: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1ff) << 5;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Pd4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      break;
    }
    case Hexagon::L4_loadbsw2_ur:
    case Hexagon::L4_loadbzw2_ur:
    case Hexagon::L4_loadrb_ur:
    case Hexagon::L4_loadrh_ur:
    case Hexagon::L4_loadri_ur:
    case Hexagon::L4_loadrub_ur:
    case Hexagon::L4_loadruh_ur: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x2) << 12;
      Value |= (op & 0x1) << 7;
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x3c) << 6;
      Value |= (op & 0x3) << 5;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::L4_loadbsw4_ur:
    case Hexagon::L4_loadbzw4_ur:
    case Hexagon::L4_loadrd_ur: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x2) << 12;
      Value |= (op & 0x1) << 7;
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x3c) << 6;
      Value |= (op & 0x3) << 5;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S4_storerbnew_rr:
    case Hexagon::S4_storerhnew_rr:
    case Hexagon::S4_storerinew_rr: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x2) << 12;
      Value |= (op & 0x1) << 7;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Ru32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Nt8
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x7);
      break;
    }
    case Hexagon::S4_storerb_rr:
    case Hexagon::S4_storerf_rr:
    case Hexagon::S4_storerh_rr:
    case Hexagon::S4_storeri_rr: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x2) << 12;
      Value |= (op & 0x1) << 7;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Ru32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S4_storerd_rr: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x2) << 12;
      Value |= (op & 0x1) << 7;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Ru32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S2_pstorerbnewf_io:
    case Hexagon::S2_pstorerbnewt_io:
    case Hexagon::S4_pstorerbnewfnew_io:
    case Hexagon::S4_pstorerbnewtnew_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x20) << 8;
      Value |= (op & 0x1f) << 3;
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Nt8
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x7) << 8;
      break;
    }
    case Hexagon::S2_pstorerbf_io:
    case Hexagon::S2_pstorerbt_io:
    case Hexagon::S4_pstorerbfnew_io:
    case Hexagon::S4_pstorerbtnew_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x20) << 8;
      Value |= (op & 0x1f) << 3;
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      break;
    }
    case Hexagon::C2_cmpeqi:
    case Hexagon::C2_cmpgti:
    case Hexagon::C4_cmpltei:
    case Hexagon::C4_cmpneqi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x200) << 12;
      Value |= (op & 0x1ff) << 5;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Pd4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      break;
    }
    case Hexagon::A2_andir:
    case Hexagon::A2_orir: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x200) << 12;
      Value |= (op & 0x1ff) << 5;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S4_subaddi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x30) << 17;
      Value |= (op & 0x8) << 10;
      Value |= (op & 0x7) << 5;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Ru32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      break;
    }
    case Hexagon::L2_loadrd_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3000) << 13;
      Value |= (op & 0xff8) << 2;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S2_storerinew_pci: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3c) << 1;
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Nt8
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::S2_storeri_pci: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3c) << 1;
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::S2_storerinew_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3c) << 1;
      // op: Nt8
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::S2_storeri_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3c) << 1;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::SL1_loadri_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3c) << 6;
      // op: Rs16
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 4;
      // op: Rd16
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf);
      break;
    }
    case Hexagon::L4_ploadrbf_abs:
    case Hexagon::L4_ploadrbfnew_abs:
    case Hexagon::L4_ploadrbt_abs:
    case Hexagon::L4_ploadrbtnew_abs:
    case Hexagon::L4_ploadrhf_abs:
    case Hexagon::L4_ploadrhfnew_abs:
    case Hexagon::L4_ploadrht_abs:
    case Hexagon::L4_ploadrhtnew_abs:
    case Hexagon::L4_ploadrif_abs:
    case Hexagon::L4_ploadrifnew_abs:
    case Hexagon::L4_ploadrit_abs:
    case Hexagon::L4_ploadritnew_abs:
    case Hexagon::L4_ploadrubf_abs:
    case Hexagon::L4_ploadrubfnew_abs:
    case Hexagon::L4_ploadrubt_abs:
    case Hexagon::L4_ploadrubtnew_abs:
    case Hexagon::L4_ploadruhf_abs:
    case Hexagon::L4_ploadruhfnew_abs:
    case Hexagon::L4_ploadruht_abs:
    case Hexagon::L4_ploadruhtnew_abs: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3e) << 15;
      Value |= (op & 0x1) << 8;
      // op: Pt4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 9;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::L4_ploadrdf_abs:
    case Hexagon::L4_ploadrdfnew_abs:
    case Hexagon::L4_ploadrdt_abs:
    case Hexagon::L4_ploadrdtnew_abs: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3e) << 15;
      Value |= (op & 0x1) << 8;
      // op: Pt4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 9;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S4_storeirbf_io:
    case Hexagon::S4_storeirbfnew_io:
    case Hexagon::S4_storeirbt_io:
    case Hexagon::S4_storeirbtnew_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3f) << 7;
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x20) << 8;
      Value |= (op & 0x1f);
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3) << 5;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::S2_extractup:
    case Hexagon::S4_extractp: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3f) << 8;
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x38) << 18;
      Value |= (op & 0x7) << 5;
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::C2_bitsclri:
    case Hexagon::C4_nbitsclri: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3f) << 8;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Pd4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      break;
    }
    case Hexagon::S4_clbaddi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3f) << 8;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S4_clbpaddi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3f) << 8;
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::A7_croundd_ri:
    case Hexagon::S2_asl_i_p:
    case Hexagon::S2_asr_i_p:
    case Hexagon::S2_asr_i_p_rnd:
    case Hexagon::S2_lsr_i_p:
    case Hexagon::S6_rol_i_p: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3f) << 8;
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S2_allocframe: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3ff8) >> 3;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::S2_pstorerhnewf_io:
    case Hexagon::S2_pstorerhnewt_io:
    case Hexagon::S4_pstorerhnewfnew_io:
    case Hexagon::S4_pstorerhnewtnew_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x40) << 7;
      Value |= (op & 0x3e) << 2;
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Nt8
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x7) << 8;
      break;
    }
    case Hexagon::S2_pstorerff_io:
    case Hexagon::S2_pstorerft_io:
    case Hexagon::S2_pstorerhf_io:
    case Hexagon::S2_pstorerht_io:
    case Hexagon::S4_pstorerffnew_io:
    case Hexagon::S4_pstorerftnew_io:
    case Hexagon::S4_pstorerhfnew_io:
    case Hexagon::S4_pstorerhtnew_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x40) << 7;
      Value |= (op & 0x3e) << 2;
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      break;
    }
    case Hexagon::J4_cmpeqn1_f_jumpnv_nt:
    case Hexagon::J4_cmpeqn1_f_jumpnv_t:
    case Hexagon::J4_cmpeqn1_t_jumpnv_nt:
    case Hexagon::J4_cmpeqn1_t_jumpnv_t:
    case Hexagon::J4_cmpgtn1_f_jumpnv_nt:
    case Hexagon::J4_cmpgtn1_f_jumpnv_t:
    case Hexagon::J4_cmpgtn1_t_jumpnv_nt:
    case Hexagon::J4_cmpgtn1_t_jumpnv_t: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x600) << 11;
      Value |= (op & 0x1fc) >> 1;
      // op: Ns8
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7) << 16;
      break;
    }
    case Hexagon::J4_cmpeq_f_jumpnv_nt:
    case Hexagon::J4_cmpeq_f_jumpnv_t:
    case Hexagon::J4_cmpeq_t_jumpnv_nt:
    case Hexagon::J4_cmpeq_t_jumpnv_t:
    case Hexagon::J4_cmpgt_f_jumpnv_nt:
    case Hexagon::J4_cmpgt_f_jumpnv_t:
    case Hexagon::J4_cmpgt_t_jumpnv_nt:
    case Hexagon::J4_cmpgt_t_jumpnv_t:
    case Hexagon::J4_cmpgtu_f_jumpnv_nt:
    case Hexagon::J4_cmpgtu_f_jumpnv_t:
    case Hexagon::J4_cmpgtu_t_jumpnv_nt:
    case Hexagon::J4_cmpgtu_t_jumpnv_t: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x600) << 11;
      Value |= (op & 0x1fc) >> 1;
      // op: Ns8
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      break;
    }
    case Hexagon::J4_cmpeqn1_fp0_jump_nt:
    case Hexagon::J4_cmpeqn1_fp0_jump_t:
    case Hexagon::J4_cmpeqn1_fp1_jump_nt:
    case Hexagon::J4_cmpeqn1_fp1_jump_t:
    case Hexagon::J4_cmpeqn1_tp0_jump_nt:
    case Hexagon::J4_cmpeqn1_tp0_jump_t:
    case Hexagon::J4_cmpeqn1_tp1_jump_nt:
    case Hexagon::J4_cmpeqn1_tp1_jump_t:
    case Hexagon::J4_cmpgtn1_fp0_jump_nt:
    case Hexagon::J4_cmpgtn1_fp0_jump_t:
    case Hexagon::J4_cmpgtn1_fp1_jump_nt:
    case Hexagon::J4_cmpgtn1_fp1_jump_t:
    case Hexagon::J4_cmpgtn1_tp0_jump_nt:
    case Hexagon::J4_cmpgtn1_tp0_jump_t:
    case Hexagon::J4_cmpgtn1_tp1_jump_nt:
    case Hexagon::J4_cmpgtn1_tp1_jump_t: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x600) << 11;
      Value |= (op & 0x1fc) >> 1;
      // op: Rs16
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 16;
      break;
    }
    case Hexagon::J4_cmpeq_fp0_jump_nt:
    case Hexagon::J4_cmpeq_fp0_jump_t:
    case Hexagon::J4_cmpeq_fp1_jump_nt:
    case Hexagon::J4_cmpeq_fp1_jump_t:
    case Hexagon::J4_cmpeq_tp0_jump_nt:
    case Hexagon::J4_cmpeq_tp0_jump_t:
    case Hexagon::J4_cmpeq_tp1_jump_nt:
    case Hexagon::J4_cmpeq_tp1_jump_t:
    case Hexagon::J4_cmpgt_fp0_jump_nt:
    case Hexagon::J4_cmpgt_fp0_jump_t:
    case Hexagon::J4_cmpgt_fp1_jump_nt:
    case Hexagon::J4_cmpgt_fp1_jump_t:
    case Hexagon::J4_cmpgt_tp0_jump_nt:
    case Hexagon::J4_cmpgt_tp0_jump_t:
    case Hexagon::J4_cmpgt_tp1_jump_nt:
    case Hexagon::J4_cmpgt_tp1_jump_t:
    case Hexagon::J4_cmpgtu_fp0_jump_nt:
    case Hexagon::J4_cmpgtu_fp0_jump_t:
    case Hexagon::J4_cmpgtu_fp1_jump_nt:
    case Hexagon::J4_cmpgtu_fp1_jump_t:
    case Hexagon::J4_cmpgtu_tp0_jump_nt:
    case Hexagon::J4_cmpgtu_tp0_jump_t:
    case Hexagon::J4_cmpgtu_tp1_jump_nt:
    case Hexagon::J4_cmpgtu_tp1_jump_t: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x600) << 11;
      Value |= (op & 0x1fc) >> 1;
      // op: Rs16
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 16;
      // op: Rt16
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 8;
      break;
    }
    case Hexagon::J4_jumpsetr: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x600) << 11;
      Value |= (op & 0x1fc) >> 1;
      // op: Rs16
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 16;
      // op: Rd16
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf) << 8;
      break;
    }
    case Hexagon::J4_cmplt_f_jumpnv_nt:
    case Hexagon::J4_cmplt_f_jumpnv_t:
    case Hexagon::J4_cmplt_t_jumpnv_nt:
    case Hexagon::J4_cmplt_t_jumpnv_t:
    case Hexagon::J4_cmpltu_f_jumpnv_nt:
    case Hexagon::J4_cmpltu_f_jumpnv_t:
    case Hexagon::J4_cmpltu_t_jumpnv_nt:
    case Hexagon::J4_cmpltu_t_jumpnv_t: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x600) << 11;
      Value |= (op & 0x1fc) >> 1;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Ns8
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7) << 16;
      break;
    }
    case Hexagon::L2_loadrb_io:
    case Hexagon::L2_loadrub_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x600) << 16;
      Value |= (op & 0x1ff) << 5;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vS32b_new_pi:
    case Hexagon::V6_vS32b_nt_new_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: Os8
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x7);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::SL2_loadrb_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: Rs16
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 4;
      // op: Rd16
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf);
      break;
    }
    case Hexagon::V6_vS32b_srls_pi:
    case Hexagon::V6_zLd_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::V6_vS32Ub_pi:
    case Hexagon::V6_vS32b_nt_pi:
    case Hexagon::V6_vS32b_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: Vs32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::S2_storerd_pci: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x78);
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::S2_storerd_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x78);
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::S4_storeirhf_io:
    case Hexagon::S4_storeirhfnew_io:
    case Hexagon::S4_storeirht_io:
    case Hexagon::S4_storeirhtnew_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x7e) << 6;
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x20) << 8;
      Value |= (op & 0x1f);
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3) << 5;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::SA1_addi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x7f) << 4;
      // op: Rx16
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf);
      break;
    }
    case Hexagon::A4_cmpbgtui:
    case Hexagon::A4_cmphgtui: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x7f) << 5;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Pd4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      break;
    }
    case Hexagon::A4_vcmpbgtui:
    case Hexagon::A4_vcmphgtui:
    case Hexagon::A4_vcmpwgtui: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x7f) << 5;
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Pd4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      break;
    }
    case Hexagon::V6_zLd_pred_ai: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x8) << 10;
      Value |= (op & 0x7) << 8;
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3) << 11;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::V6_vS32b_new_npred_ai:
    case Hexagon::V6_vS32b_new_pred_ai:
    case Hexagon::V6_vS32b_nt_new_npred_ai:
    case Hexagon::V6_vS32b_nt_new_pred_ai: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x8) << 10;
      Value |= (op & 0x7) << 8;
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3) << 11;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Os8
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x7);
      break;
    }
    case Hexagon::V6_vS32Ub_npred_ai:
    case Hexagon::V6_vS32Ub_pred_ai:
    case Hexagon::V6_vS32b_npred_ai:
    case Hexagon::V6_vS32b_nt_npred_ai:
    case Hexagon::V6_vS32b_nt_pred_ai:
    case Hexagon::V6_vS32b_pred_ai: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x8) << 10;
      Value |= (op & 0x7) << 8;
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3) << 11;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vs32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vS32b_nqpred_ai:
    case Hexagon::V6_vS32b_nt_nqpred_ai:
    case Hexagon::V6_vS32b_nt_qpred_ai:
    case Hexagon::V6_vS32b_qpred_ai: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x8) << 10;
      Value |= (op & 0x7) << 8;
      // op: Qv4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3) << 11;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vs32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vL32Ub_ai:
    case Hexagon::V6_vL32b_ai:
    case Hexagon::V6_vL32b_cur_ai:
    case Hexagon::V6_vL32b_nt_ai:
    case Hexagon::V6_vL32b_nt_cur_ai:
    case Hexagon::V6_vL32b_nt_tmp_ai:
    case Hexagon::V6_vL32b_tmp_ai: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x8) << 10;
      Value |= (op & 0x7) << 8;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S2_pstorerinewf_io:
    case Hexagon::S2_pstorerinewt_io:
    case Hexagon::S4_pstorerinewfnew_io:
    case Hexagon::S4_pstorerinewtnew_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x80) << 6;
      Value |= (op & 0x7c) << 1;
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Nt8
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x7) << 8;
      break;
    }
    case Hexagon::S2_pstorerif_io:
    case Hexagon::S2_pstorerit_io:
    case Hexagon::S4_pstorerifnew_io:
    case Hexagon::S4_pstoreritnew_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x80) << 6;
      Value |= (op & 0x7c) << 1;
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      break;
    }
    case Hexagon::M4_mpyri_addr_u2: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xc0) << 15;
      Value |= (op & 0x20) << 8;
      Value |= (op & 0x1c) << 3;
      // op: Ru32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      break;
    }
    case Hexagon::L2_loadbsw2_io:
    case Hexagon::L2_loadbzw2_io:
    case Hexagon::L2_loadrh_io:
    case Hexagon::L2_loadruh_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xc00) << 15;
      Value |= (op & 0x3fe) << 4;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::A2_tfrih:
    case Hexagon::A2_tfril: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xc000) << 8;
      Value |= (op & 0x3fff);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::SL2_loadrh_io:
    case Hexagon::SL2_loadruh_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xe) << 7;
      // op: Rs16
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 4;
      // op: Rd16
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf);
      break;
    }
    case Hexagon::S2_storerbnew_pci: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xf) << 3;
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Nt8
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::S2_storerb_pci: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xf) << 3;
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::S2_storerbnew_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xf) << 3;
      // op: Nt8
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::S2_storerb_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xf) << 3;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::SL1_loadrub_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xf) << 8;
      // op: Rs16
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 4;
      // op: Rd16
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf);
      break;
    }
    case Hexagon::S5_asrhub_rnd_sat:
    case Hexagon::S5_asrhub_sat: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xf) << 8;
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S2_asl_i_vh:
    case Hexagon::S2_asr_i_vh:
    case Hexagon::S2_lsr_i_vh:
    case Hexagon::S5_vasrhrnd: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xf) << 8;
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::C2_cmoveif:
    case Hexagon::C2_cmoveit:
    case Hexagon::C2_cmovenewif:
    case Hexagon::C2_cmovenewit: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xf00) << 8;
      Value |= (op & 0xff) << 5;
      // op: Pu4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 21;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::J2_trap1: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xf8) << 5;
      Value |= (op & 0x7) << 2;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::S4_storeirif_io:
    case Hexagon::S4_storeirifnew_io:
    case Hexagon::S4_storeirit_io:
    case Hexagon::S4_storeiritnew_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xfc) << 5;
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x20) << 8;
      Value |= (op & 0x1f);
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3) << 5;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::A2_addi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xfe00) << 12;
      Value |= (op & 0x1ff) << 5;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::C2_muxii: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xff) << 5;
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0xfe) << 15;
      Value |= (op & 0x1) << 13;
      // op: Pu4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 23;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::C2_muxri: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xff) << 5;
      // op: Pu4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 21;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::A4_cmpbeqi:
    case Hexagon::A4_cmpbgti:
    case Hexagon::A4_cmpheqi:
    case Hexagon::A4_cmphgti: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xff) << 5;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Pd4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      break;
    }
    case Hexagon::A4_rcmpeqi:
    case Hexagon::A4_rcmpneqi:
    case Hexagon::M2_mpysin:
    case Hexagon::M2_mpysip: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xff) << 5;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::A4_combineri: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xff) << 5;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::A4_vcmpbeqi:
    case Hexagon::A4_vcmpbgti:
    case Hexagon::A4_vcmpheqi:
    case Hexagon::A4_vcmphgti:
    case Hexagon::A4_vcmpweqi:
    case Hexagon::A4_vcmpwgti: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xff) << 5;
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Pd4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      break;
    }
    case Hexagon::V6_vrmpybusi:
    case Hexagon::V6_vrmpyubi:
    case Hexagon::V6_vrsadubi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1) << 5;
      // op: Vuu32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S2_pstorerhnewf_pi:
    case Hexagon::S2_pstorerhnewfnew_pi:
    case Hexagon::S2_pstorerhnewt_pi:
    case Hexagon::S2_pstorerhnewtnew_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1e) << 2;
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3);
      // op: Nt8
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::S2_pstorerff_pi:
    case Hexagon::S2_pstorerffnew_pi:
    case Hexagon::S2_pstorerft_pi:
    case Hexagon::S2_pstorerftnew_pi:
    case Hexagon::S2_pstorerhf_pi:
    case Hexagon::S2_pstorerhfnew_pi:
    case Hexagon::S2_pstorerht_pi:
    case Hexagon::S2_pstorerhtnew_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1e) << 2;
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3);
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::L2_loadbsw2_pci:
    case Hexagon::L2_loadbzw2_pci:
    case Hexagon::L2_loadrh_pci:
    case Hexagon::L2_loadruh_pci: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1e) << 4;
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::L2_loadbsw2_pi:
    case Hexagon::L2_loadbzw2_pi:
    case Hexagon::L2_loadrh_pi:
    case Hexagon::L2_loadruh_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1e) << 4;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::S2_insert: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x18) << 18;
      Value |= (op & 0x7) << 5;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S2_asl_i_r_acc:
    case Hexagon::S2_asl_i_r_and:
    case Hexagon::S2_asl_i_r_nac:
    case Hexagon::S2_asl_i_r_or:
    case Hexagon::S2_asl_i_r_xacc:
    case Hexagon::S2_asr_i_r_acc:
    case Hexagon::S2_asr_i_r_and:
    case Hexagon::S2_asr_i_r_nac:
    case Hexagon::S2_asr_i_r_or:
    case Hexagon::S2_lsr_i_r_acc:
    case Hexagon::S2_lsr_i_r_and:
    case Hexagon::S2_lsr_i_r_nac:
    case Hexagon::S2_lsr_i_r_or:
    case Hexagon::S2_lsr_i_r_xacc:
    case Hexagon::S6_rol_i_r_acc:
    case Hexagon::S6_rol_i_r_and:
    case Hexagon::S6_rol_i_r_nac:
    case Hexagon::S6_rol_i_r_or:
    case Hexagon::S6_rol_i_r_xacc: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::L2_ploadrdf_io:
    case Hexagon::L2_ploadrdfnew_io:
    case Hexagon::L2_ploadrdt_io:
    case Hexagon::L2_ploadrdtnew_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f8) << 2;
      // op: Pt4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 11;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S4_vrcrotate: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x2) << 12;
      Value |= (op & 0x1) << 5;
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::L4_loadalignb_ur:
    case Hexagon::L4_loadalignh_ur: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x2) << 12;
      Value |= (op & 0x1) << 7;
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x3c) << 6;
      Value |= (op & 0x3) << 5;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Ryy32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S4_pstorerbnewf_rr:
    case Hexagon::S4_pstorerbnewfnew_rr:
    case Hexagon::S4_pstorerbnewt_rr:
    case Hexagon::S4_pstorerbnewtnew_rr:
    case Hexagon::S4_pstorerhnewf_rr:
    case Hexagon::S4_pstorerhnewfnew_rr:
    case Hexagon::S4_pstorerhnewt_rr:
    case Hexagon::S4_pstorerhnewtnew_rr:
    case Hexagon::S4_pstorerinewf_rr:
    case Hexagon::S4_pstorerinewfnew_rr:
    case Hexagon::S4_pstorerinewt_rr:
    case Hexagon::S4_pstorerinewtnew_rr: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x2) << 12;
      Value |= (op & 0x1) << 7;
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3) << 5;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Ru32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Nt8
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x7);
      break;
    }
    case Hexagon::S4_pstorerbf_rr:
    case Hexagon::S4_pstorerbfnew_rr:
    case Hexagon::S4_pstorerbt_rr:
    case Hexagon::S4_pstorerbtnew_rr:
    case Hexagon::S4_pstorerff_rr:
    case Hexagon::S4_pstorerffnew_rr:
    case Hexagon::S4_pstorerft_rr:
    case Hexagon::S4_pstorerftnew_rr:
    case Hexagon::S4_pstorerhf_rr:
    case Hexagon::S4_pstorerhfnew_rr:
    case Hexagon::S4_pstorerht_rr:
    case Hexagon::S4_pstorerhtnew_rr:
    case Hexagon::S4_pstorerif_rr:
    case Hexagon::S4_pstorerifnew_rr:
    case Hexagon::S4_pstorerit_rr:
    case Hexagon::S4_pstoreritnew_rr: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x2) << 12;
      Value |= (op & 0x1) << 7;
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3) << 5;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Ru32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S4_pstorerdf_rr:
    case Hexagon::S4_pstorerdfnew_rr:
    case Hexagon::S4_pstorerdt_rr:
    case Hexagon::S4_pstorerdtnew_rr: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x2) << 12;
      Value |= (op & 0x1) << 7;
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3) << 5;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Ru32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::L4_loadrb_rr:
    case Hexagon::L4_loadrh_rr:
    case Hexagon::L4_loadri_rr:
    case Hexagon::L4_loadrub_rr:
    case Hexagon::L4_loadruh_rr: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x2) << 12;
      Value |= (op & 0x1) << 7;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::L4_loadrd_rr: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x2) << 12;
      Value |= (op & 0x1) << 7;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S4_or_andi:
    case Hexagon::S4_or_ori: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x200) << 12;
      Value |= (op & 0x1ff) << 5;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S4_or_andix: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x200) << 12;
      Value |= (op & 0x1ff) << 5;
      // op: Ru32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::V6_v6mpyhubs10:
    case Hexagon::V6_v6mpyvubs10: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x3) << 5;
      // op: Vuu32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vvv32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S4_addaddi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x30) << 17;
      Value |= (op & 0x8) << 10;
      Value |= (op & 0x7) << 5;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Ru32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      break;
    }
    case Hexagon::M4_mpyri_addr: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x30) << 17;
      Value |= (op & 0x8) << 10;
      Value |= (op & 0x7) << 5;
      // op: Ru32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      break;
    }
    case Hexagon::S2_pstorerinewf_pi:
    case Hexagon::S2_pstorerinewfnew_pi:
    case Hexagon::S2_pstorerinewt_pi:
    case Hexagon::S2_pstorerinewtnew_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x3c) << 1;
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3);
      // op: Nt8
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::S2_pstorerif_pi:
    case Hexagon::S2_pstorerifnew_pi:
    case Hexagon::S2_pstorerit_pi:
    case Hexagon::S2_pstoreritnew_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x3c) << 1;
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3);
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::L2_loadri_pci: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x3c) << 3;
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::L2_loadbsw4_pci:
    case Hexagon::L2_loadbzw4_pci: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x3c) << 3;
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::L2_loadri_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x3c) << 3;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::L2_loadbsw4_pi:
    case Hexagon::L2_loadbzw4_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x3c) << 3;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::L2_ploadrbf_io:
    case Hexagon::L2_ploadrbfnew_io:
    case Hexagon::L2_ploadrbt_io:
    case Hexagon::L2_ploadrbtnew_io:
    case Hexagon::L2_ploadrubf_io:
    case Hexagon::L2_ploadrubfnew_io:
    case Hexagon::L2_ploadrubt_io:
    case Hexagon::L2_ploadrubtnew_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x3f) << 5;
      // op: Pt4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 11;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S2_insertp: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x3f) << 8;
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x38) << 18;
      Value |= (op & 0x7) << 5;
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rxx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S2_asl_i_p_acc:
    case Hexagon::S2_asl_i_p_and:
    case Hexagon::S2_asl_i_p_nac:
    case Hexagon::S2_asl_i_p_or:
    case Hexagon::S2_asl_i_p_xacc:
    case Hexagon::S2_asr_i_p_acc:
    case Hexagon::S2_asr_i_p_and:
    case Hexagon::S2_asr_i_p_nac:
    case Hexagon::S2_asr_i_p_or:
    case Hexagon::S2_lsr_i_p_acc:
    case Hexagon::S2_lsr_i_p_and:
    case Hexagon::S2_lsr_i_p_nac:
    case Hexagon::S2_lsr_i_p_or:
    case Hexagon::S2_lsr_i_p_xacc:
    case Hexagon::S6_rol_i_p_acc:
    case Hexagon::S6_rol_i_p_and:
    case Hexagon::S6_rol_i_p_nac:
    case Hexagon::S6_rol_i_p_or:
    case Hexagon::S6_rol_i_p_xacc: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x3f) << 8;
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rxx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::L2_loadalignb_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x600) << 16;
      Value |= (op & 0x1ff) << 5;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Ryy32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S2_vspliceib: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x7) << 5;
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S2_addasl_rrri: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x7) << 5;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S2_valignib: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x7) << 5;
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_valignbi:
    case Hexagon::V6_vlalignbi:
    case Hexagon::V6_vlutvvbi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x7) << 5;
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vv32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vlutvwhi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x7) << 5;
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vv32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vS32b_new_npred_pi:
    case Hexagon::V6_vS32b_new_pred_pi:
    case Hexagon::V6_vS32b_nt_new_npred_pi:
    case Hexagon::V6_vS32b_nt_new_pred_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 11;
      // op: Os8
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x7);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::V6_zLd_pred_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 11;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::V6_vS32Ub_npred_pi:
    case Hexagon::V6_vS32Ub_pred_pi:
    case Hexagon::V6_vS32b_npred_pi:
    case Hexagon::V6_vS32b_nt_npred_pi:
    case Hexagon::V6_vS32b_nt_pred_pi:
    case Hexagon::V6_vS32b_pred_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 11;
      // op: Vs32
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::V6_vS32b_nqpred_pi:
    case Hexagon::V6_vS32b_nt_nqpred_pi:
    case Hexagon::V6_vS32b_nt_qpred_pi:
    case Hexagon::V6_vS32b_qpred_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: Qv4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 11;
      // op: Vs32
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::V6_vL32Ub_pi:
    case Hexagon::V6_vL32b_cur_pi:
    case Hexagon::V6_vL32b_nt_cur_pi:
    case Hexagon::V6_vL32b_nt_pi:
    case Hexagon::V6_vL32b_nt_tmp_pi:
    case Hexagon::V6_vL32b_pi:
    case Hexagon::V6_vL32b_tmp_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: Vd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::L2_loadrd_pci: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x78) << 2;
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::L2_loadrd_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x78) << 2;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::S2_pstorerdf_pi:
    case Hexagon::S2_pstorerdfnew_pi:
    case Hexagon::S2_pstorerdt_pi:
    case Hexagon::S2_pstorerdtnew_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x78);
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3);
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::L2_ploadrhf_io:
    case Hexagon::L2_ploadrhfnew_io:
    case Hexagon::L2_ploadrht_io:
    case Hexagon::L2_ploadrhtnew_io:
    case Hexagon::L2_ploadruhf_io:
    case Hexagon::L2_ploadruhfnew_io:
    case Hexagon::L2_ploadruht_io:
    case Hexagon::L2_ploadruhtnew_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x7e) << 4;
      // op: Pt4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 11;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vL32b_cur_npred_ai:
    case Hexagon::V6_vL32b_cur_pred_ai:
    case Hexagon::V6_vL32b_npred_ai:
    case Hexagon::V6_vL32b_nt_cur_npred_ai:
    case Hexagon::V6_vL32b_nt_cur_pred_ai:
    case Hexagon::V6_vL32b_nt_npred_ai:
    case Hexagon::V6_vL32b_nt_pred_ai:
    case Hexagon::V6_vL32b_nt_tmp_npred_ai:
    case Hexagon::V6_vL32b_nt_tmp_pred_ai:
    case Hexagon::V6_vL32b_pred_ai:
    case Hexagon::V6_vL32b_tmp_npred_ai:
    case Hexagon::V6_vL32b_tmp_pred_ai: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x8) << 10;
      Value |= (op & 0x7) << 8;
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 11;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S2_tableidxb:
    case Hexagon::S2_tableidxd:
    case Hexagon::S2_tableidxh:
    case Hexagon::S2_tableidxw: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x8) << 18;
      Value |= (op & 0x7) << 5;
      // op: II
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x3f) << 8;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::L2_loadalignh_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0xc00) << 15;
      Value |= (op & 0x3fe) << 4;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Ryy32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S2_pstorerbnewf_pi:
    case Hexagon::S2_pstorerbnewfnew_pi:
    case Hexagon::S2_pstorerbnewt_pi:
    case Hexagon::S2_pstorerbnewtnew_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0xf) << 3;
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3);
      // op: Nt8
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::S2_pstorerbf_pi:
    case Hexagon::S2_pstorerbfnew_pi:
    case Hexagon::S2_pstorerbt_pi:
    case Hexagon::S2_pstorerbtnew_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0xf) << 3;
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3);
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::L2_loadrb_pci:
    case Hexagon::L2_loadrub_pci: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0xf) << 5;
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::L2_loadrb_pi:
    case Hexagon::L2_loadrub_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0xf) << 5;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::L2_ploadrif_io:
    case Hexagon::L2_ploadrifnew_io:
    case Hexagon::L2_ploadrit_io:
    case Hexagon::L2_ploadritnew_io: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0xfc) << 3;
      // op: Pt4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 11;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::A2_paddif:
    case Hexagon::A2_paddifnew:
    case Hexagon::A2_paddit:
    case Hexagon::A2_padditnew:
    case Hexagon::C2_muxir: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0xff) << 5;
      // op: Pu4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 21;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::M2_accii:
    case Hexagon::M2_macsin:
    case Hexagon::M2_macsip:
    case Hexagon::M2_naccii: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0xff) << 5;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vrmpybusi_acc:
    case Hexagon::V6_vrmpyubi_acc:
    case Hexagon::V6_vrsadubi_acc: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1) << 5;
      // op: Vuu32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vxx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::L2_loadalignh_pci: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1e) << 4;
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(5), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Ryy32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::L2_ploadrhf_pi:
    case Hexagon::L2_ploadrhfnew_pi:
    case Hexagon::L2_ploadrht_pi:
    case Hexagon::L2_ploadrhtnew_pi:
    case Hexagon::L2_ploadruhf_pi:
    case Hexagon::L2_ploadruhfnew_pi:
    case Hexagon::L2_ploadruht_pi:
    case Hexagon::L2_ploadruhtnew_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1e) << 4;
      // op: Pt4
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3) << 9;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::L2_loadalignh_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1e) << 4;
      // op: Ryy32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::S4_vrcrotate_acc: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x2) << 12;
      Value |= (op & 0x1) << 5;
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rxx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::L4_ploadrbf_rr:
    case Hexagon::L4_ploadrbfnew_rr:
    case Hexagon::L4_ploadrbt_rr:
    case Hexagon::L4_ploadrbtnew_rr:
    case Hexagon::L4_ploadrhf_rr:
    case Hexagon::L4_ploadrhfnew_rr:
    case Hexagon::L4_ploadrht_rr:
    case Hexagon::L4_ploadrhtnew_rr:
    case Hexagon::L4_ploadrif_rr:
    case Hexagon::L4_ploadrifnew_rr:
    case Hexagon::L4_ploadrit_rr:
    case Hexagon::L4_ploadritnew_rr:
    case Hexagon::L4_ploadrubf_rr:
    case Hexagon::L4_ploadrubfnew_rr:
    case Hexagon::L4_ploadrubt_rr:
    case Hexagon::L4_ploadrubtnew_rr:
    case Hexagon::L4_ploadruhf_rr:
    case Hexagon::L4_ploadruhfnew_rr:
    case Hexagon::L4_ploadruht_rr:
    case Hexagon::L4_ploadruhtnew_rr: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x2) << 12;
      Value |= (op & 0x1) << 7;
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 5;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::L4_ploadrdf_rr:
    case Hexagon::L4_ploadrdfnew_rr:
    case Hexagon::L4_ploadrdt_rr:
    case Hexagon::L4_ploadrdtnew_rr: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x2) << 12;
      Value |= (op & 0x1) << 7;
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 5;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_v6mpyhubs10_vxx:
    case Hexagon::V6_v6mpyvubs10_vxx: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x3) << 5;
      // op: Vuu32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vvv32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vxx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::L2_ploadrif_pi:
    case Hexagon::L2_ploadrifnew_pi:
    case Hexagon::L2_ploadrit_pi:
    case Hexagon::L2_ploadritnew_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x3c) << 3;
      // op: Pt4
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3) << 9;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::V6_vlutvvb_oracci: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x7) << 5;
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vv32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vlutvwh_oracci: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x7) << 5;
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vv32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vxx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vL32b_cur_npred_pi:
    case Hexagon::V6_vL32b_cur_pred_pi:
    case Hexagon::V6_vL32b_npred_pi:
    case Hexagon::V6_vL32b_nt_cur_npred_pi:
    case Hexagon::V6_vL32b_nt_cur_pred_pi:
    case Hexagon::V6_vL32b_nt_npred_pi:
    case Hexagon::V6_vL32b_nt_pred_pi:
    case Hexagon::V6_vL32b_nt_tmp_npred_pi:
    case Hexagon::V6_vL32b_nt_tmp_pred_pi:
    case Hexagon::V6_vL32b_pred_pi:
    case Hexagon::V6_vL32b_tmp_npred_pi:
    case Hexagon::V6_vL32b_tmp_pred_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3) << 11;
      // op: Vd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::L2_ploadrdf_pi:
    case Hexagon::L2_ploadrdfnew_pi:
    case Hexagon::L2_ploadrdt_pi:
    case Hexagon::L2_ploadrdtnew_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x78) << 2;
      // op: Pt4
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3) << 9;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::L2_loadalignb_pci: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0xf) << 5;
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(5), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Ryy32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::L2_ploadrbf_pi:
    case Hexagon::L2_ploadrbfnew_pi:
    case Hexagon::L2_ploadrbt_pi:
    case Hexagon::L2_ploadrbtnew_pi:
    case Hexagon::L2_ploadrubf_pi:
    case Hexagon::L2_ploadrubfnew_pi:
    case Hexagon::L2_ploadrubt_pi:
    case Hexagon::L2_ploadrubtnew_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0xf) << 5;
      // op: Pt4
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3) << 9;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::L2_loadalignb_pi: {
      // op: Ii
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0xf) << 5;
      // op: Ryy32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::S2_storerbnew_pbr:
    case Hexagon::S2_storerbnew_pcr:
    case Hexagon::S2_storerbnew_pr:
    case Hexagon::S2_storerhnew_pbr:
    case Hexagon::S2_storerhnew_pcr:
    case Hexagon::S2_storerhnew_pr:
    case Hexagon::S2_storerinew_pbr:
    case Hexagon::S2_storerinew_pcr:
    case Hexagon::S2_storerinew_pr: {
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Nt8
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x7) << 8;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::V6_vS32b_new_ppu:
    case Hexagon::V6_vS32b_nt_new_ppu: {
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Os8
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x7);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::S2_storerb_pbr:
    case Hexagon::S2_storerb_pcr:
    case Hexagon::S2_storerb_pr:
    case Hexagon::S2_storerf_pbr:
    case Hexagon::S2_storerf_pcr:
    case Hexagon::S2_storerf_pr:
    case Hexagon::S2_storerh_pbr:
    case Hexagon::S2_storerh_pcr:
    case Hexagon::S2_storerh_pr:
    case Hexagon::S2_storeri_pbr:
    case Hexagon::S2_storeri_pcr:
    case Hexagon::S2_storeri_pr: {
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::S2_storerd_pbr:
    case Hexagon::S2_storerd_pcr:
    case Hexagon::S2_storerd_pr: {
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::V6_vS32b_srls_ppu:
    case Hexagon::V6_zLd_ppu: {
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::V6_vS32Ub_ppu:
    case Hexagon::V6_vS32b_nt_ppu:
    case Hexagon::V6_vS32b_ppu: {
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Vs32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::L2_loadbsw2_pbr:
    case Hexagon::L2_loadbsw2_pcr:
    case Hexagon::L2_loadbsw2_pr:
    case Hexagon::L2_loadbzw2_pbr:
    case Hexagon::L2_loadbzw2_pcr:
    case Hexagon::L2_loadbzw2_pr:
    case Hexagon::L2_loadrb_pbr:
    case Hexagon::L2_loadrb_pcr:
    case Hexagon::L2_loadrb_pr:
    case Hexagon::L2_loadrh_pbr:
    case Hexagon::L2_loadrh_pcr:
    case Hexagon::L2_loadrh_pr:
    case Hexagon::L2_loadri_pbr:
    case Hexagon::L2_loadri_pcr:
    case Hexagon::L2_loadri_pr:
    case Hexagon::L2_loadrub_pbr:
    case Hexagon::L2_loadrub_pcr:
    case Hexagon::L2_loadrub_pr:
    case Hexagon::L2_loadruh_pbr:
    case Hexagon::L2_loadruh_pcr:
    case Hexagon::L2_loadruh_pr: {
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::L2_loadbsw4_pbr:
    case Hexagon::L2_loadbsw4_pcr:
    case Hexagon::L2_loadbsw4_pr:
    case Hexagon::L2_loadbzw4_pbr:
    case Hexagon::L2_loadbzw4_pcr:
    case Hexagon::L2_loadbzw4_pr:
    case Hexagon::L2_loadrd_pbr:
    case Hexagon::L2_loadrd_pcr:
    case Hexagon::L2_loadrd_pr: {
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::V6_vL32Ub_ppu:
    case Hexagon::V6_vL32b_cur_ppu:
    case Hexagon::V6_vL32b_nt_cur_ppu:
    case Hexagon::V6_vL32b_nt_ppu:
    case Hexagon::V6_vL32b_nt_tmp_ppu:
    case Hexagon::V6_vL32b_ppu:
    case Hexagon::V6_vL32b_tmp_ppu: {
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Vd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::L2_loadalignb_pbr:
    case Hexagon::L2_loadalignb_pcr:
    case Hexagon::L2_loadalignb_pr:
    case Hexagon::L2_loadalignh_pbr:
    case Hexagon::L2_loadalignh_pcr:
    case Hexagon::L2_loadalignh_pr: {
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Ryy32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::C2_all8:
    case Hexagon::C2_any8:
    case Hexagon::C2_not: {
      // op: Ps4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 16;
      // op: Pd4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      break;
    }
    case Hexagon::C2_xor:
    case Hexagon::C4_fastcorner9:
    case Hexagon::C4_fastcorner9_not: {
      // op: Ps4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 16;
      // op: Pt4
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3) << 8;
      // op: Pd4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      break;
    }
    case Hexagon::C4_and_and:
    case Hexagon::C4_and_andn:
    case Hexagon::C4_and_or:
    case Hexagon::C4_and_orn:
    case Hexagon::C4_or_and:
    case Hexagon::C4_or_andn:
    case Hexagon::C4_or_or:
    case Hexagon::C4_or_orn: {
      // op: Ps4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 16;
      // op: Pt4
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3) << 8;
      // op: Pu4
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x3) << 6;
      // op: Pd4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      break;
    }
    case Hexagon::C2_vitpack: {
      // op: Ps4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 16;
      // op: Pt4
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3) << 8;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::C2_tfrpr: {
      // op: Ps4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vcmov:
    case Hexagon::V6_vncmov: {
      // op: Ps4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 5;
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vccombine:
    case Hexagon::V6_vnccombine: {
      // op: Ps4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 5;
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vv32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::Y2_setimask:
    case Hexagon::Y2_setprio: {
      // op: Pt4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3) << 8;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::C2_and:
    case Hexagon::C2_andn:
    case Hexagon::C2_or:
    case Hexagon::C2_orn: {
      // op: Pt4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 8;
      // op: Ps4
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3) << 16;
      // op: Pd4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      break;
    }
    case Hexagon::C2_mask: {
      // op: Pt4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 8;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::J2_callrf:
    case Hexagon::J2_callrt:
    case Hexagon::J2_jumprf:
    case Hexagon::J2_jumprfnew:
    case Hexagon::J2_jumprfnewpt:
    case Hexagon::J2_jumprfpt:
    case Hexagon::J2_jumprt:
    case Hexagon::J2_jumprtnew:
    case Hexagon::J2_jumprtnewpt:
    case Hexagon::J2_jumprtpt: {
      // op: Pu4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3) << 8;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::A2_paddf:
    case Hexagon::A2_paddfnew:
    case Hexagon::A2_paddt:
    case Hexagon::A2_paddtnew:
    case Hexagon::A2_pandf:
    case Hexagon::A2_pandfnew:
    case Hexagon::A2_pandt:
    case Hexagon::A2_pandtnew:
    case Hexagon::A2_porf:
    case Hexagon::A2_porfnew:
    case Hexagon::A2_port:
    case Hexagon::A2_portnew:
    case Hexagon::A2_pxorf:
    case Hexagon::A2_pxorfnew:
    case Hexagon::A2_pxort:
    case Hexagon::A2_pxortnew:
    case Hexagon::C2_mux: {
      // op: Pu4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 5;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::C2_ccombinewf:
    case Hexagon::C2_ccombinewnewf:
    case Hexagon::C2_ccombinewnewt:
    case Hexagon::C2_ccombinewt: {
      // op: Pu4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 5;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::C2_vmux: {
      // op: Pu4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 5;
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::A2_psubf:
    case Hexagon::A2_psubfnew:
    case Hexagon::A2_psubt:
    case Hexagon::A2_psubtnew: {
      // op: Pu4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 5;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::A4_paslhf:
    case Hexagon::A4_paslhfnew:
    case Hexagon::A4_paslht:
    case Hexagon::A4_paslhtnew:
    case Hexagon::A4_pasrhf:
    case Hexagon::A4_pasrhfnew:
    case Hexagon::A4_pasrht:
    case Hexagon::A4_pasrhtnew:
    case Hexagon::A4_psxtbf:
    case Hexagon::A4_psxtbfnew:
    case Hexagon::A4_psxtbt:
    case Hexagon::A4_psxtbtnew:
    case Hexagon::A4_psxthf:
    case Hexagon::A4_psxthfnew:
    case Hexagon::A4_psxtht:
    case Hexagon::A4_psxthtnew:
    case Hexagon::A4_pzxtbf:
    case Hexagon::A4_pzxtbfnew:
    case Hexagon::A4_pzxtbt:
    case Hexagon::A4_pzxtbtnew:
    case Hexagon::A4_pzxthf:
    case Hexagon::A4_pzxthfnew:
    case Hexagon::A4_pzxtht:
    case Hexagon::A4_pzxthtnew: {
      // op: Pu4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 8;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vS32b_new_npred_ppu:
    case Hexagon::V6_vS32b_new_pred_ppu:
    case Hexagon::V6_vS32b_nt_new_npred_ppu:
    case Hexagon::V6_vS32b_nt_new_pred_ppu: {
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 11;
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Os8
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x7);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::V6_zLd_pred_ppu: {
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 11;
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::V6_vS32Ub_npred_ppu:
    case Hexagon::V6_vS32Ub_pred_ppu:
    case Hexagon::V6_vS32b_npred_ppu:
    case Hexagon::V6_vS32b_nt_npred_ppu:
    case Hexagon::V6_vS32b_nt_pred_ppu:
    case Hexagon::V6_vS32b_pred_ppu: {
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 11;
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Vs32
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::L4_return_f:
    case Hexagon::L4_return_fnew_pnt:
    case Hexagon::L4_return_fnew_pt:
    case Hexagon::L4_return_t:
    case Hexagon::L4_return_tnew_pnt:
    case Hexagon::L4_return_tnew_pt: {
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 8;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vL32b_cur_npred_ppu:
    case Hexagon::V6_vL32b_cur_pred_ppu:
    case Hexagon::V6_vL32b_npred_ppu:
    case Hexagon::V6_vL32b_nt_cur_npred_ppu:
    case Hexagon::V6_vL32b_nt_cur_pred_ppu:
    case Hexagon::V6_vL32b_nt_npred_ppu:
    case Hexagon::V6_vL32b_nt_pred_ppu:
    case Hexagon::V6_vL32b_nt_tmp_npred_ppu:
    case Hexagon::V6_vL32b_nt_tmp_pred_ppu:
    case Hexagon::V6_vL32b_pred_ppu:
    case Hexagon::V6_vL32b_tmp_npred_ppu:
    case Hexagon::V6_vL32b_tmp_pred_ppu: {
      // op: Pv4
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3) << 11;
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Vd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::V6_vscattermhq:
    case Hexagon::V6_vscattermwq: {
      // op: Qs4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3) << 5;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Vv32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vw32
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vgathermhq:
    case Hexagon::V6_vgathermwq: {
      // op: Qs4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3) << 5;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Vv32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vscattermhwq: {
      // op: Qs4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3) << 5;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Vvv32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vw32
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vgathermhwq: {
      // op: Qs4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3) << 5;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Vvv32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_pred_not: {
      // op: Qs4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 8;
      // op: Qd4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      break;
    }
    case Hexagon::V6_pred_and:
    case Hexagon::V6_pred_and_n:
    case Hexagon::V6_pred_or:
    case Hexagon::V6_pred_or_n:
    case Hexagon::V6_pred_xor:
    case Hexagon::V6_shuffeqh:
    case Hexagon::V6_shuffeqw: {
      // op: Qs4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 8;
      // op: Qt4
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3) << 22;
      // op: Qd4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      break;
    }
    case Hexagon::V6_vmux: {
      // op: Qt4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 5;
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vv32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vswap: {
      // op: Qt4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 5;
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vv32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vandnqrt:
    case Hexagon::V6_vandqrt: {
      // op: Qu4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 8;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vandnqrt_acc:
    case Hexagon::V6_vandqrt_acc: {
      // op: Qu4
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x3) << 8;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vhistq:
    case Hexagon::V6_vwhist128q:
    case Hexagon::V6_vwhist256q:
    case Hexagon::V6_vwhist256q_sat: {
      // op: Qv4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3) << 22;
      break;
    }
    case Hexagon::V6_vS32b_nqpred_ppu:
    case Hexagon::V6_vS32b_nt_nqpred_ppu:
    case Hexagon::V6_vS32b_nt_qpred_ppu:
    case Hexagon::V6_vS32b_qpred_ppu: {
      // op: Qv4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 11;
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Vs32
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::V6_vprefixqb:
    case Hexagon::V6_vprefixqh:
    case Hexagon::V6_vprefixqw: {
      // op: Qv4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 22;
      // op: Vd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vandvnqv:
    case Hexagon::V6_vandvqv: {
      // op: Qv4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 22;
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vaddbnq:
    case Hexagon::V6_vaddbq:
    case Hexagon::V6_vaddhnq:
    case Hexagon::V6_vaddhq:
    case Hexagon::V6_vaddwnq:
    case Hexagon::V6_vaddwq:
    case Hexagon::V6_vsubbnq:
    case Hexagon::V6_vsubbq:
    case Hexagon::V6_vsubhnq:
    case Hexagon::V6_vsubhq:
    case Hexagon::V6_vsubwnq:
    case Hexagon::V6_vsubwq: {
      // op: Qv4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 22;
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::SA1_clrf:
    case Hexagon::SA1_clrfnew:
    case Hexagon::SA1_clrt:
    case Hexagon::SA1_clrtnew:
    case Hexagon::SA1_setin1: {
      // op: Rd16
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf);
      break;
    }
    case Hexagon::Y6_dmpause:
    case Hexagon::Y6_dmpoll:
    case Hexagon::Y6_dmwait: {
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::PS_callr_nr: {
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::SA1_and1:
    case Hexagon::SA1_dec:
    case Hexagon::SA1_inc:
    case Hexagon::SA1_sxtb:
    case Hexagon::SA1_sxth:
    case Hexagon::SA1_tfr:
    case Hexagon::SA1_zxtb:
    case Hexagon::SA1_zxth: {
      // op: Rs16
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 4;
      // op: Rd16
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf);
      break;
    }
    case Hexagon::SA1_combinerz:
    case Hexagon::SA1_combinezr: {
      // op: Rs16
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xf) << 4;
      // op: Rdd8
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7);
      break;
    }
    case Hexagon::SA1_addrx: {
      // op: Rs16
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0xf) << 4;
      // op: Rx16
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xf);
      break;
    }
    case Hexagon::J2_callr:
    case Hexagon::J2_callrh:
    case Hexagon::J2_jumpr:
    case Hexagon::J2_jumprh:
    case Hexagon::J4_hintjumpr:
    case Hexagon::R6_release_at_vi:
    case Hexagon::R6_release_st_vi:
    case Hexagon::Y2_ciad:
    case Hexagon::Y2_cswi:
    case Hexagon::Y2_dccleana:
    case Hexagon::Y2_dccleanidx:
    case Hexagon::Y2_dccleaninva:
    case Hexagon::Y2_dccleaninvidx:
    case Hexagon::Y2_dcinva:
    case Hexagon::Y2_dcinvidx:
    case Hexagon::Y2_dczeroa:
    case Hexagon::Y2_iassignw:
    case Hexagon::Y2_icinva:
    case Hexagon::Y2_icinvidx:
    case Hexagon::Y2_l2cleaninvidx:
    case Hexagon::Y2_resume:
    case Hexagon::Y2_start:
    case Hexagon::Y2_stop:
    case Hexagon::Y2_swi:
    case Hexagon::Y2_wait:
    case Hexagon::Y4_nmi:
    case Hexagon::Y4_siad:
    case Hexagon::Y4_trace:
    case Hexagon::Y5_l2cleanidx:
    case Hexagon::Y5_l2invidx:
    case Hexagon::Y5_l2unlocka:
    case Hexagon::Y5_tlbasidi:
    case Hexagon::Y6_diag:
    case Hexagon::Y6_dmresume:
    case Hexagon::Y6_dmstart: {
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::S2_storew_rl_at_vi:
    case Hexagon::S2_storew_rl_st_vi:
    case Hexagon::Y2_dctagw:
    case Hexagon::Y2_icdataw:
    case Hexagon::Y2_ictagw:
    case Hexagon::Y4_l2fetch:
    case Hexagon::Y4_l2tagw:
    case Hexagon::Y6_dmlink: {
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      break;
    }
    case Hexagon::L6_memcpy: {
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1) << 13;
      break;
    }
    case Hexagon::S4_stored_rl_at_vi:
    case Hexagon::S4_stored_rl_st_vi:
    case Hexagon::Y5_l2fetch: {
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      break;
    }
    case Hexagon::A2_tfrrcr: {
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Cd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::G4_tfrgrcr: {
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Gd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::C2_tfrrp:
    case Hexagon::Y5_l2locka: {
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Pd4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      break;
    }
    case Hexagon::A2_abs:
    case Hexagon::A2_abssat:
    case Hexagon::A2_aslh:
    case Hexagon::A2_asrh:
    case Hexagon::A2_negsat:
    case Hexagon::A2_satb:
    case Hexagon::A2_sath:
    case Hexagon::A2_satub:
    case Hexagon::A2_satuh:
    case Hexagon::A2_swiz:
    case Hexagon::A2_sxtb:
    case Hexagon::A2_sxth:
    case Hexagon::A2_tfr:
    case Hexagon::A2_zxth:
    case Hexagon::F2_conv_sf2uw:
    case Hexagon::F2_conv_sf2uw_chop:
    case Hexagon::F2_conv_sf2w:
    case Hexagon::F2_conv_sf2w_chop:
    case Hexagon::F2_conv_uw2sf:
    case Hexagon::F2_conv_w2sf:
    case Hexagon::F2_sffixupr:
    case Hexagon::L2_loadw_aq:
    case Hexagon::L2_loadw_locked:
    case Hexagon::S2_brev:
    case Hexagon::S2_cl0:
    case Hexagon::S2_cl1:
    case Hexagon::S2_clb:
    case Hexagon::S2_clbnorm:
    case Hexagon::S2_ct0:
    case Hexagon::S2_ct1:
    case Hexagon::S2_svsathb:
    case Hexagon::S2_svsathub:
    case Hexagon::S2_vsplatrb:
    case Hexagon::Y2_dctagr:
    case Hexagon::Y2_getimask:
    case Hexagon::Y2_iassignr:
    case Hexagon::Y2_icdatar:
    case Hexagon::Y2_ictagr:
    case Hexagon::Y2_tlbp:
    case Hexagon::Y4_l2tagr: {
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::A2_sxtw:
    case Hexagon::F2_conv_sf2d:
    case Hexagon::F2_conv_sf2d_chop:
    case Hexagon::F2_conv_sf2df:
    case Hexagon::F2_conv_sf2ud:
    case Hexagon::F2_conv_sf2ud_chop:
    case Hexagon::F2_conv_uw2df:
    case Hexagon::F2_conv_w2df:
    case Hexagon::L2_deallocframe:
    case Hexagon::L4_loadd_aq:
    case Hexagon::L4_loadd_locked:
    case Hexagon::L4_return:
    case Hexagon::S2_vsplatrh:
    case Hexagon::S2_vsxtbh:
    case Hexagon::S2_vsxthw:
    case Hexagon::S2_vzxtbh:
    case Hexagon::S2_vzxthw:
    case Hexagon::S6_vsplatrbp:
    case Hexagon::Y2_tlbr: {
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::A4_cmpbeq:
    case Hexagon::A4_cmpbgt:
    case Hexagon::A4_cmpbgtu:
    case Hexagon::A4_cmpheq:
    case Hexagon::A4_cmphgt:
    case Hexagon::A4_cmphgtu:
    case Hexagon::C2_bitsclr:
    case Hexagon::C2_bitsset:
    case Hexagon::C2_cmpeq:
    case Hexagon::C2_cmpgt:
    case Hexagon::C2_cmpgtu:
    case Hexagon::C4_cmplte:
    case Hexagon::C4_cmplteu:
    case Hexagon::C4_cmpneq:
    case Hexagon::C4_nbitsclr:
    case Hexagon::C4_nbitsset:
    case Hexagon::F2_sfcmpeq:
    case Hexagon::F2_sfcmpge:
    case Hexagon::F2_sfcmpgt:
    case Hexagon::F2_sfcmpuo:
    case Hexagon::S2_storew_locked:
    case Hexagon::S2_tstbit_r:
    case Hexagon::S4_ntstbit_r: {
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Pd4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      break;
    }
    case Hexagon::A2_add:
    case Hexagon::A2_addsat:
    case Hexagon::A2_and:
    case Hexagon::A2_max:
    case Hexagon::A2_maxu:
    case Hexagon::A2_or:
    case Hexagon::A2_svaddh:
    case Hexagon::A2_svaddhs:
    case Hexagon::A2_svadduhs:
    case Hexagon::A2_svavgh:
    case Hexagon::A2_svavghs:
    case Hexagon::A2_xor:
    case Hexagon::A4_cround_rr:
    case Hexagon::A4_modwrapu:
    case Hexagon::A4_rcmpeq:
    case Hexagon::A4_rcmpneq:
    case Hexagon::A4_round_rr:
    case Hexagon::A4_round_rr_sat:
    case Hexagon::F2_sfadd:
    case Hexagon::F2_sffixupd:
    case Hexagon::F2_sffixupn:
    case Hexagon::F2_sfmax:
    case Hexagon::F2_sfmin:
    case Hexagon::F2_sfmpy:
    case Hexagon::F2_sfsub:
    case Hexagon::L4_loadw_phys:
    case Hexagon::M2_cmpyrs_s0:
    case Hexagon::M2_cmpyrs_s1:
    case Hexagon::M2_cmpyrsc_s0:
    case Hexagon::M2_cmpyrsc_s1:
    case Hexagon::M2_dpmpyss_rnd_s0:
    case Hexagon::M2_hmmpyh_rs1:
    case Hexagon::M2_hmmpyh_s1:
    case Hexagon::M2_hmmpyl_rs1:
    case Hexagon::M2_hmmpyl_s1:
    case Hexagon::M2_mpy_hh_s0:
    case Hexagon::M2_mpy_hh_s1:
    case Hexagon::M2_mpy_hl_s0:
    case Hexagon::M2_mpy_hl_s1:
    case Hexagon::M2_mpy_lh_s0:
    case Hexagon::M2_mpy_lh_s1:
    case Hexagon::M2_mpy_ll_s0:
    case Hexagon::M2_mpy_ll_s1:
    case Hexagon::M2_mpy_rnd_hh_s0:
    case Hexagon::M2_mpy_rnd_hh_s1:
    case Hexagon::M2_mpy_rnd_hl_s0:
    case Hexagon::M2_mpy_rnd_hl_s1:
    case Hexagon::M2_mpy_rnd_lh_s0:
    case Hexagon::M2_mpy_rnd_lh_s1:
    case Hexagon::M2_mpy_rnd_ll_s0:
    case Hexagon::M2_mpy_rnd_ll_s1:
    case Hexagon::M2_mpy_sat_hh_s0:
    case Hexagon::M2_mpy_sat_hh_s1:
    case Hexagon::M2_mpy_sat_hl_s0:
    case Hexagon::M2_mpy_sat_hl_s1:
    case Hexagon::M2_mpy_sat_lh_s0:
    case Hexagon::M2_mpy_sat_lh_s1:
    case Hexagon::M2_mpy_sat_ll_s0:
    case Hexagon::M2_mpy_sat_ll_s1:
    case Hexagon::M2_mpy_sat_rnd_hh_s0:
    case Hexagon::M2_mpy_sat_rnd_hh_s1:
    case Hexagon::M2_mpy_sat_rnd_hl_s0:
    case Hexagon::M2_mpy_sat_rnd_hl_s1:
    case Hexagon::M2_mpy_sat_rnd_lh_s0:
    case Hexagon::M2_mpy_sat_rnd_lh_s1:
    case Hexagon::M2_mpy_sat_rnd_ll_s0:
    case Hexagon::M2_mpy_sat_rnd_ll_s1:
    case Hexagon::M2_mpy_up:
    case Hexagon::M2_mpy_up_s1:
    case Hexagon::M2_mpy_up_s1_sat:
    case Hexagon::M2_mpyi:
    case Hexagon::M2_mpysu_up:
    case Hexagon::M2_mpyu_hh_s0:
    case Hexagon::M2_mpyu_hh_s1:
    case Hexagon::M2_mpyu_hl_s0:
    case Hexagon::M2_mpyu_hl_s1:
    case Hexagon::M2_mpyu_lh_s0:
    case Hexagon::M2_mpyu_lh_s1:
    case Hexagon::M2_mpyu_ll_s0:
    case Hexagon::M2_mpyu_ll_s1:
    case Hexagon::M2_mpyu_up:
    case Hexagon::M2_vmpy2s_s0pack:
    case Hexagon::M2_vmpy2s_s1pack:
    case Hexagon::S2_asl_r_r:
    case Hexagon::S2_asl_r_r_sat:
    case Hexagon::S2_asr_r_r:
    case Hexagon::S2_asr_r_r_sat:
    case Hexagon::S2_clrbit_r:
    case Hexagon::S2_lsl_r_r:
    case Hexagon::S2_lsr_r_r:
    case Hexagon::S2_setbit_r:
    case Hexagon::S2_togglebit_r:
    case Hexagon::S4_parity:
    case Hexagon::dep_A2_addsat: {
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::A2_combinew:
    case Hexagon::A4_bitsplit:
    case Hexagon::M2_cmpyi_s0:
    case Hexagon::M2_cmpyr_s0:
    case Hexagon::M2_cmpys_s0:
    case Hexagon::M2_cmpys_s1:
    case Hexagon::M2_cmpysc_s0:
    case Hexagon::M2_cmpysc_s1:
    case Hexagon::M2_dpmpyss_s0:
    case Hexagon::M2_dpmpyuu_s0:
    case Hexagon::M2_mpyd_hh_s0:
    case Hexagon::M2_mpyd_hh_s1:
    case Hexagon::M2_mpyd_hl_s0:
    case Hexagon::M2_mpyd_hl_s1:
    case Hexagon::M2_mpyd_lh_s0:
    case Hexagon::M2_mpyd_lh_s1:
    case Hexagon::M2_mpyd_ll_s0:
    case Hexagon::M2_mpyd_ll_s1:
    case Hexagon::M2_mpyd_rnd_hh_s0:
    case Hexagon::M2_mpyd_rnd_hh_s1:
    case Hexagon::M2_mpyd_rnd_hl_s0:
    case Hexagon::M2_mpyd_rnd_hl_s1:
    case Hexagon::M2_mpyd_rnd_lh_s0:
    case Hexagon::M2_mpyd_rnd_lh_s1:
    case Hexagon::M2_mpyd_rnd_ll_s0:
    case Hexagon::M2_mpyd_rnd_ll_s1:
    case Hexagon::M2_mpyud_hh_s0:
    case Hexagon::M2_mpyud_hh_s1:
    case Hexagon::M2_mpyud_hl_s0:
    case Hexagon::M2_mpyud_hl_s1:
    case Hexagon::M2_mpyud_lh_s0:
    case Hexagon::M2_mpyud_lh_s1:
    case Hexagon::M2_mpyud_ll_s0:
    case Hexagon::M2_mpyud_ll_s1:
    case Hexagon::M2_vmpy2s_s0:
    case Hexagon::M2_vmpy2s_s1:
    case Hexagon::M2_vmpy2su_s0:
    case Hexagon::M2_vmpy2su_s1:
    case Hexagon::M4_pmpyw:
    case Hexagon::M4_vpmpyh:
    case Hexagon::M5_vmpybsu:
    case Hexagon::M5_vmpybuu:
    case Hexagon::S2_packhl:
    case Hexagon::dep_S2_packhl: {
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S4_stored_locked: {
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Pd4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      break;
    }
    case Hexagon::S2_extractu_rp:
    case Hexagon::S4_extract_rp: {
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::Y2_tfrsrcr: {
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Sd128
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7f);
      break;
    }
    case Hexagon::F2_sfinvsqrta: {
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Pe4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 5;
      break;
    }
    case Hexagon::F2_sffma_sc: {
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Pu4
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x3) << 5;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::F2_sfrecipa: {
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Pe4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 5;
      break;
    }
    case Hexagon::F2_sffma:
    case Hexagon::F2_sffma_lib:
    case Hexagon::F2_sffms:
    case Hexagon::F2_sffms_lib:
    case Hexagon::M2_acci:
    case Hexagon::M2_maci:
    case Hexagon::M2_mnaci:
    case Hexagon::M2_mpy_acc_hh_s0:
    case Hexagon::M2_mpy_acc_hh_s1:
    case Hexagon::M2_mpy_acc_hl_s0:
    case Hexagon::M2_mpy_acc_hl_s1:
    case Hexagon::M2_mpy_acc_lh_s0:
    case Hexagon::M2_mpy_acc_lh_s1:
    case Hexagon::M2_mpy_acc_ll_s0:
    case Hexagon::M2_mpy_acc_ll_s1:
    case Hexagon::M2_mpy_acc_sat_hh_s0:
    case Hexagon::M2_mpy_acc_sat_hh_s1:
    case Hexagon::M2_mpy_acc_sat_hl_s0:
    case Hexagon::M2_mpy_acc_sat_hl_s1:
    case Hexagon::M2_mpy_acc_sat_lh_s0:
    case Hexagon::M2_mpy_acc_sat_lh_s1:
    case Hexagon::M2_mpy_acc_sat_ll_s0:
    case Hexagon::M2_mpy_acc_sat_ll_s1:
    case Hexagon::M2_mpy_nac_hh_s0:
    case Hexagon::M2_mpy_nac_hh_s1:
    case Hexagon::M2_mpy_nac_hl_s0:
    case Hexagon::M2_mpy_nac_hl_s1:
    case Hexagon::M2_mpy_nac_lh_s0:
    case Hexagon::M2_mpy_nac_lh_s1:
    case Hexagon::M2_mpy_nac_ll_s0:
    case Hexagon::M2_mpy_nac_ll_s1:
    case Hexagon::M2_mpy_nac_sat_hh_s0:
    case Hexagon::M2_mpy_nac_sat_hh_s1:
    case Hexagon::M2_mpy_nac_sat_hl_s0:
    case Hexagon::M2_mpy_nac_sat_hl_s1:
    case Hexagon::M2_mpy_nac_sat_lh_s0:
    case Hexagon::M2_mpy_nac_sat_lh_s1:
    case Hexagon::M2_mpy_nac_sat_ll_s0:
    case Hexagon::M2_mpy_nac_sat_ll_s1:
    case Hexagon::M2_mpyu_acc_hh_s0:
    case Hexagon::M2_mpyu_acc_hh_s1:
    case Hexagon::M2_mpyu_acc_hl_s0:
    case Hexagon::M2_mpyu_acc_hl_s1:
    case Hexagon::M2_mpyu_acc_lh_s0:
    case Hexagon::M2_mpyu_acc_lh_s1:
    case Hexagon::M2_mpyu_acc_ll_s0:
    case Hexagon::M2_mpyu_acc_ll_s1:
    case Hexagon::M2_mpyu_nac_hh_s0:
    case Hexagon::M2_mpyu_nac_hh_s1:
    case Hexagon::M2_mpyu_nac_hl_s0:
    case Hexagon::M2_mpyu_nac_hl_s1:
    case Hexagon::M2_mpyu_nac_lh_s0:
    case Hexagon::M2_mpyu_nac_lh_s1:
    case Hexagon::M2_mpyu_nac_ll_s0:
    case Hexagon::M2_mpyu_nac_ll_s1:
    case Hexagon::M2_nacci:
    case Hexagon::M2_xor_xacc:
    case Hexagon::M4_and_and:
    case Hexagon::M4_and_andn:
    case Hexagon::M4_and_or:
    case Hexagon::M4_and_xor:
    case Hexagon::M4_mac_up_s1_sat:
    case Hexagon::M4_nac_up_s1_sat:
    case Hexagon::M4_or_and:
    case Hexagon::M4_or_andn:
    case Hexagon::M4_or_or:
    case Hexagon::M4_or_xor:
    case Hexagon::M4_xor_and:
    case Hexagon::M4_xor_andn:
    case Hexagon::M4_xor_or:
    case Hexagon::S2_asl_r_r_acc:
    case Hexagon::S2_asl_r_r_and:
    case Hexagon::S2_asl_r_r_nac:
    case Hexagon::S2_asl_r_r_or:
    case Hexagon::S2_asr_r_r_acc:
    case Hexagon::S2_asr_r_r_and:
    case Hexagon::S2_asr_r_r_nac:
    case Hexagon::S2_asr_r_r_or:
    case Hexagon::S2_lsl_r_r_acc:
    case Hexagon::S2_lsl_r_r_and:
    case Hexagon::S2_lsl_r_r_nac:
    case Hexagon::S2_lsl_r_r_or:
    case Hexagon::S2_lsr_r_r_acc:
    case Hexagon::S2_lsr_r_r_and:
    case Hexagon::S2_lsr_r_r_nac:
    case Hexagon::S2_lsr_r_r_or: {
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::M2_cmaci_s0:
    case Hexagon::M2_cmacr_s0:
    case Hexagon::M2_cmacs_s0:
    case Hexagon::M2_cmacs_s1:
    case Hexagon::M2_cmacsc_s0:
    case Hexagon::M2_cmacsc_s1:
    case Hexagon::M2_cnacs_s0:
    case Hexagon::M2_cnacs_s1:
    case Hexagon::M2_cnacsc_s0:
    case Hexagon::M2_cnacsc_s1:
    case Hexagon::M2_dpmpyss_acc_s0:
    case Hexagon::M2_dpmpyss_nac_s0:
    case Hexagon::M2_dpmpyuu_acc_s0:
    case Hexagon::M2_dpmpyuu_nac_s0:
    case Hexagon::M2_mpyd_acc_hh_s0:
    case Hexagon::M2_mpyd_acc_hh_s1:
    case Hexagon::M2_mpyd_acc_hl_s0:
    case Hexagon::M2_mpyd_acc_hl_s1:
    case Hexagon::M2_mpyd_acc_lh_s0:
    case Hexagon::M2_mpyd_acc_lh_s1:
    case Hexagon::M2_mpyd_acc_ll_s0:
    case Hexagon::M2_mpyd_acc_ll_s1:
    case Hexagon::M2_mpyd_nac_hh_s0:
    case Hexagon::M2_mpyd_nac_hh_s1:
    case Hexagon::M2_mpyd_nac_hl_s0:
    case Hexagon::M2_mpyd_nac_hl_s1:
    case Hexagon::M2_mpyd_nac_lh_s0:
    case Hexagon::M2_mpyd_nac_lh_s1:
    case Hexagon::M2_mpyd_nac_ll_s0:
    case Hexagon::M2_mpyd_nac_ll_s1:
    case Hexagon::M2_mpyud_acc_hh_s0:
    case Hexagon::M2_mpyud_acc_hh_s1:
    case Hexagon::M2_mpyud_acc_hl_s0:
    case Hexagon::M2_mpyud_acc_hl_s1:
    case Hexagon::M2_mpyud_acc_lh_s0:
    case Hexagon::M2_mpyud_acc_lh_s1:
    case Hexagon::M2_mpyud_acc_ll_s0:
    case Hexagon::M2_mpyud_acc_ll_s1:
    case Hexagon::M2_mpyud_nac_hh_s0:
    case Hexagon::M2_mpyud_nac_hh_s1:
    case Hexagon::M2_mpyud_nac_hl_s0:
    case Hexagon::M2_mpyud_nac_hl_s1:
    case Hexagon::M2_mpyud_nac_lh_s0:
    case Hexagon::M2_mpyud_nac_lh_s1:
    case Hexagon::M2_mpyud_nac_ll_s0:
    case Hexagon::M2_mpyud_nac_ll_s1:
    case Hexagon::M2_vmac2:
    case Hexagon::M2_vmac2s_s0:
    case Hexagon::M2_vmac2s_s1:
    case Hexagon::M2_vmac2su_s0:
    case Hexagon::M2_vmac2su_s1:
    case Hexagon::M4_pmpyw_acc:
    case Hexagon::M4_vpmpyh_acc:
    case Hexagon::M5_vmacbsu:
    case Hexagon::M5_vmacbuu: {
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rxx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::S2_insert_rp: {
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::Y2_tlbw: {
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      break;
    }
    case Hexagon::Y6_diag0:
    case Hexagon::Y6_diag1: {
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      break;
    }
    case Hexagon::A4_tfrpcp: {
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Cdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::G4_tfrgpcp: {
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Gdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::A2_roundsat:
    case Hexagon::A2_sat:
    case Hexagon::F2_conv_d2sf:
    case Hexagon::F2_conv_df2sf:
    case Hexagon::F2_conv_df2uw:
    case Hexagon::F2_conv_df2uw_chop:
    case Hexagon::F2_conv_df2w:
    case Hexagon::F2_conv_df2w_chop:
    case Hexagon::F2_conv_ud2sf:
    case Hexagon::S2_cl0p:
    case Hexagon::S2_cl1p:
    case Hexagon::S2_clbp:
    case Hexagon::S2_ct0p:
    case Hexagon::S2_ct1p:
    case Hexagon::S2_vrndpackwh:
    case Hexagon::S2_vrndpackwhs:
    case Hexagon::S2_vsathb:
    case Hexagon::S2_vsathub:
    case Hexagon::S2_vsatwh:
    case Hexagon::S2_vsatwuh:
    case Hexagon::S2_vtrunehb:
    case Hexagon::S2_vtrunohb:
    case Hexagon::S4_clbpnorm:
    case Hexagon::S5_popcountp:
    case Hexagon::Y2_tlbpp:
    case Hexagon::Y5_tlboc: {
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::A2_absp:
    case Hexagon::A2_negp:
    case Hexagon::A2_notp:
    case Hexagon::A2_vabsh:
    case Hexagon::A2_vabshsat:
    case Hexagon::A2_vabsw:
    case Hexagon::A2_vabswsat:
    case Hexagon::A2_vconj:
    case Hexagon::F2_conv_d2df:
    case Hexagon::F2_conv_df2d:
    case Hexagon::F2_conv_df2d_chop:
    case Hexagon::F2_conv_df2ud:
    case Hexagon::F2_conv_df2ud_chop:
    case Hexagon::F2_conv_ud2df:
    case Hexagon::S2_brevp:
    case Hexagon::S2_deinterleave:
    case Hexagon::S2_interleave:
    case Hexagon::S2_vsathb_nopack:
    case Hexagon::S2_vsathub_nopack:
    case Hexagon::S2_vsatwh_nopack:
    case Hexagon::S2_vsatwuh_nopack: {
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::A4_tlbmatch: {
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Pd4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      break;
    }
    case Hexagon::M4_cmpyi_wh:
    case Hexagon::M4_cmpyi_whc:
    case Hexagon::M4_cmpyr_wh:
    case Hexagon::M4_cmpyr_whc:
    case Hexagon::S2_asr_r_svw_trun:
    case Hexagon::Y5_ctlbw: {
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::A7_croundd_rr:
    case Hexagon::S2_asl_r_p:
    case Hexagon::S2_asl_r_vh:
    case Hexagon::S2_asl_r_vw:
    case Hexagon::S2_asr_r_p:
    case Hexagon::S2_asr_r_vh:
    case Hexagon::S2_asr_r_vw:
    case Hexagon::S2_lsl_r_p:
    case Hexagon::S2_lsl_r_vh:
    case Hexagon::S2_lsl_r_vw:
    case Hexagon::S2_lsr_r_p:
    case Hexagon::S2_lsr_r_vh:
    case Hexagon::S2_lsr_r_vw:
    case Hexagon::S2_vcnegh:
    case Hexagon::S2_vcrotate: {
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::A2_vcmpbeq:
    case Hexagon::A2_vcmpbgtu:
    case Hexagon::A2_vcmpheq:
    case Hexagon::A2_vcmphgt:
    case Hexagon::A2_vcmphgtu:
    case Hexagon::A2_vcmpweq:
    case Hexagon::A2_vcmpwgt:
    case Hexagon::A2_vcmpwgtu:
    case Hexagon::A4_boundscheck_hi:
    case Hexagon::A4_boundscheck_lo:
    case Hexagon::A4_vcmpbeq_any:
    case Hexagon::A4_vcmpbgt:
    case Hexagon::A6_vcmpbeq_notany:
    case Hexagon::C2_cmpeqp:
    case Hexagon::C2_cmpgtp:
    case Hexagon::C2_cmpgtup:
    case Hexagon::F2_dfcmpeq:
    case Hexagon::F2_dfcmpge:
    case Hexagon::F2_dfcmpgt:
    case Hexagon::F2_dfcmpuo: {
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Pd4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      break;
    }
    case Hexagon::S2_vsplicerb: {
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Pu4
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x3) << 5;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::A5_vaddhubs:
    case Hexagon::M2_vdmpyrs_s0:
    case Hexagon::M2_vdmpyrs_s1:
    case Hexagon::M2_vraddh:
    case Hexagon::M2_vradduh:
    case Hexagon::M2_vrcmpys_s1rp_h:
    case Hexagon::M2_vrcmpys_s1rp_l:
    case Hexagon::M7_wcmpyiw:
    case Hexagon::M7_wcmpyiw_rnd:
    case Hexagon::M7_wcmpyiwc:
    case Hexagon::M7_wcmpyiwc_rnd:
    case Hexagon::M7_wcmpyrw:
    case Hexagon::M7_wcmpyrw_rnd:
    case Hexagon::M7_wcmpyrwc:
    case Hexagon::M7_wcmpyrwc_rnd:
    case Hexagon::S2_parityp: {
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::A2_addp:
    case Hexagon::A2_addpsat:
    case Hexagon::A2_addsph:
    case Hexagon::A2_addspl:
    case Hexagon::A2_andp:
    case Hexagon::A2_maxp:
    case Hexagon::A2_maxup:
    case Hexagon::A2_orp:
    case Hexagon::A2_vaddh:
    case Hexagon::A2_vaddhs:
    case Hexagon::A2_vaddub:
    case Hexagon::A2_vaddubs:
    case Hexagon::A2_vadduhs:
    case Hexagon::A2_vaddw:
    case Hexagon::A2_vaddws:
    case Hexagon::A2_vavgh:
    case Hexagon::A2_vavghcr:
    case Hexagon::A2_vavghr:
    case Hexagon::A2_vavgub:
    case Hexagon::A2_vavgubr:
    case Hexagon::A2_vavguh:
    case Hexagon::A2_vavguhr:
    case Hexagon::A2_vavguw:
    case Hexagon::A2_vavguwr:
    case Hexagon::A2_vavgw:
    case Hexagon::A2_vavgwcr:
    case Hexagon::A2_vavgwr:
    case Hexagon::A2_vraddub:
    case Hexagon::A2_vrsadub:
    case Hexagon::A2_xorp:
    case Hexagon::F2_dfadd:
    case Hexagon::F2_dfmax:
    case Hexagon::F2_dfmin:
    case Hexagon::F2_dfmpyfix:
    case Hexagon::F2_dfmpyll:
    case Hexagon::F2_dfsub:
    case Hexagon::M2_mmpyh_rs0:
    case Hexagon::M2_mmpyh_rs1:
    case Hexagon::M2_mmpyh_s0:
    case Hexagon::M2_mmpyh_s1:
    case Hexagon::M2_mmpyl_rs0:
    case Hexagon::M2_mmpyl_rs1:
    case Hexagon::M2_mmpyl_s0:
    case Hexagon::M2_mmpyl_s1:
    case Hexagon::M2_mmpyuh_rs0:
    case Hexagon::M2_mmpyuh_rs1:
    case Hexagon::M2_mmpyuh_s0:
    case Hexagon::M2_mmpyuh_s1:
    case Hexagon::M2_mmpyul_rs0:
    case Hexagon::M2_mmpyul_rs1:
    case Hexagon::M2_mmpyul_s0:
    case Hexagon::M2_mmpyul_s1:
    case Hexagon::M2_vcmpy_s0_sat_i:
    case Hexagon::M2_vcmpy_s0_sat_r:
    case Hexagon::M2_vcmpy_s1_sat_i:
    case Hexagon::M2_vcmpy_s1_sat_r:
    case Hexagon::M2_vdmpys_s0:
    case Hexagon::M2_vdmpys_s1:
    case Hexagon::M2_vmpy2es_s0:
    case Hexagon::M2_vmpy2es_s1:
    case Hexagon::M2_vrcmpyi_s0:
    case Hexagon::M2_vrcmpyi_s0c:
    case Hexagon::M2_vrcmpyr_s0:
    case Hexagon::M2_vrcmpyr_s0c:
    case Hexagon::M2_vrcmpys_s1_h:
    case Hexagon::M2_vrcmpys_s1_l:
    case Hexagon::M2_vrmpy_s0:
    case Hexagon::M4_vrmpyeh_s0:
    case Hexagon::M4_vrmpyeh_s1:
    case Hexagon::M4_vrmpyoh_s0:
    case Hexagon::M4_vrmpyoh_s1:
    case Hexagon::M5_vdmpybsu:
    case Hexagon::M5_vrmpybsu:
    case Hexagon::M5_vrmpybuu:
    case Hexagon::M7_dcmpyiw:
    case Hexagon::M7_dcmpyiwc:
    case Hexagon::M7_dcmpyrw:
    case Hexagon::M7_dcmpyrwc:
    case Hexagon::S2_cabacdecbin:
    case Hexagon::S2_extractup_rp:
    case Hexagon::S2_lfsp:
    case Hexagon::S2_shuffeb:
    case Hexagon::S2_shuffeh:
    case Hexagon::S2_vtrunewh:
    case Hexagon::S2_vtrunowh:
    case Hexagon::S4_extractp_rp:
    case Hexagon::S4_vxaddsubh:
    case Hexagon::S4_vxaddsubhr:
    case Hexagon::S4_vxaddsubw:
    case Hexagon::S4_vxsubaddh:
    case Hexagon::S4_vxsubaddhr:
    case Hexagon::S4_vxsubaddw:
    case Hexagon::S6_vtrunehb_ppp:
    case Hexagon::S6_vtrunohb_ppp: {
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::Y4_tfrspcp: {
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Sdd128
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x7f);
      break;
    }
    case Hexagon::S2_asl_r_p_acc:
    case Hexagon::S2_asl_r_p_and:
    case Hexagon::S2_asl_r_p_nac:
    case Hexagon::S2_asl_r_p_or:
    case Hexagon::S2_asl_r_p_xor:
    case Hexagon::S2_asr_r_p_acc:
    case Hexagon::S2_asr_r_p_and:
    case Hexagon::S2_asr_r_p_nac:
    case Hexagon::S2_asr_r_p_or:
    case Hexagon::S2_asr_r_p_xor:
    case Hexagon::S2_lsl_r_p_acc:
    case Hexagon::S2_lsl_r_p_and:
    case Hexagon::S2_lsl_r_p_nac:
    case Hexagon::S2_lsl_r_p_or:
    case Hexagon::S2_lsl_r_p_xor:
    case Hexagon::S2_lsr_r_p_acc:
    case Hexagon::S2_lsr_r_p_and:
    case Hexagon::S2_lsr_r_p_nac:
    case Hexagon::S2_lsr_r_p_or:
    case Hexagon::S2_lsr_r_p_xor:
    case Hexagon::S2_vrcnegh: {
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rxx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::A4_addp_c:
    case Hexagon::A4_subp_c: {
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Px4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 5;
      break;
    }
    case Hexagon::A2_vraddub_acc:
    case Hexagon::A2_vrsadub_acc:
    case Hexagon::F2_dfmpyhh:
    case Hexagon::F2_dfmpylh:
    case Hexagon::M2_mmachs_rs0:
    case Hexagon::M2_mmachs_rs1:
    case Hexagon::M2_mmachs_s0:
    case Hexagon::M2_mmachs_s1:
    case Hexagon::M2_mmacls_rs0:
    case Hexagon::M2_mmacls_rs1:
    case Hexagon::M2_mmacls_s0:
    case Hexagon::M2_mmacls_s1:
    case Hexagon::M2_mmacuhs_rs0:
    case Hexagon::M2_mmacuhs_rs1:
    case Hexagon::M2_mmacuhs_s0:
    case Hexagon::M2_mmacuhs_s1:
    case Hexagon::M2_mmaculs_rs0:
    case Hexagon::M2_mmaculs_rs1:
    case Hexagon::M2_mmaculs_s0:
    case Hexagon::M2_mmaculs_s1:
    case Hexagon::M2_vcmac_s0_sat_i:
    case Hexagon::M2_vcmac_s0_sat_r:
    case Hexagon::M2_vdmacs_s0:
    case Hexagon::M2_vdmacs_s1:
    case Hexagon::M2_vmac2es:
    case Hexagon::M2_vmac2es_s0:
    case Hexagon::M2_vmac2es_s1:
    case Hexagon::M2_vrcmaci_s0:
    case Hexagon::M2_vrcmaci_s0c:
    case Hexagon::M2_vrcmacr_s0:
    case Hexagon::M2_vrcmacr_s0c:
    case Hexagon::M2_vrcmpys_acc_s1_h:
    case Hexagon::M2_vrcmpys_acc_s1_l:
    case Hexagon::M2_vrmac_s0:
    case Hexagon::M4_vrmpyeh_acc_s0:
    case Hexagon::M4_vrmpyeh_acc_s1:
    case Hexagon::M4_vrmpyoh_acc_s0:
    case Hexagon::M4_vrmpyoh_acc_s1:
    case Hexagon::M4_xor_xacc:
    case Hexagon::M5_vdmacbsu:
    case Hexagon::M5_vrmacbsu:
    case Hexagon::M5_vrmacbuu:
    case Hexagon::M7_dcmpyiw_acc:
    case Hexagon::M7_dcmpyiwc_acc:
    case Hexagon::M7_dcmpyrw_acc:
    case Hexagon::M7_dcmpyrwc_acc:
    case Hexagon::S2_insertp_rp: {
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rxx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::A4_vrmaxh:
    case Hexagon::A4_vrmaxuh:
    case Hexagon::A4_vrmaxuw:
    case Hexagon::A4_vrmaxw:
    case Hexagon::A4_vrminh:
    case Hexagon::A4_vrminuh:
    case Hexagon::A4_vrminuw:
    case Hexagon::A4_vrminw: {
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Ru32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rxx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      break;
    }
    case Hexagon::A5_ACS: {
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rxx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Pe4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 5;
      break;
    }
    case Hexagon::V6_vscattermh:
    case Hexagon::V6_vscattermh_add:
    case Hexagon::V6_vscattermw:
    case Hexagon::V6_vscattermw_add: {
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Vv32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vw32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vgathermh:
    case Hexagon::V6_vgathermw: {
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Vv32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vscattermhw:
    case Hexagon::V6_vscattermhw_add: {
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Vvv32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vw32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vgathermhw: {
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Mu2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1) << 13;
      // op: Vvv32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_pred_scalar2:
    case Hexagon::V6_pred_scalar2v2: {
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Qd4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      break;
    }
    case Hexagon::V6_lvsplatb:
    case Hexagon::V6_lvsplath:
    case Hexagon::V6_lvsplatw:
    case Hexagon::V6_zextract: {
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::A2_addh_h16_hh:
    case Hexagon::A2_addh_h16_hl:
    case Hexagon::A2_addh_h16_lh:
    case Hexagon::A2_addh_h16_ll:
    case Hexagon::A2_addh_h16_sat_hh:
    case Hexagon::A2_addh_h16_sat_hl:
    case Hexagon::A2_addh_h16_sat_lh:
    case Hexagon::A2_addh_h16_sat_ll:
    case Hexagon::A2_addh_l16_hl:
    case Hexagon::A2_addh_l16_ll:
    case Hexagon::A2_addh_l16_sat_hl:
    case Hexagon::A2_addh_l16_sat_ll:
    case Hexagon::A2_combine_hh:
    case Hexagon::A2_combine_hl:
    case Hexagon::A2_combine_lh:
    case Hexagon::A2_combine_ll:
    case Hexagon::A2_min:
    case Hexagon::A2_minu:
    case Hexagon::A2_sub:
    case Hexagon::A2_subh_h16_hh:
    case Hexagon::A2_subh_h16_hl:
    case Hexagon::A2_subh_h16_lh:
    case Hexagon::A2_subh_h16_ll:
    case Hexagon::A2_subh_h16_sat_hh:
    case Hexagon::A2_subh_h16_sat_hl:
    case Hexagon::A2_subh_h16_sat_lh:
    case Hexagon::A2_subh_h16_sat_ll:
    case Hexagon::A2_subh_l16_hl:
    case Hexagon::A2_subh_l16_ll:
    case Hexagon::A2_subh_l16_sat_hl:
    case Hexagon::A2_subh_l16_sat_ll:
    case Hexagon::A2_subsat:
    case Hexagon::A2_svnavgh:
    case Hexagon::A2_svsubh:
    case Hexagon::A2_svsubhs:
    case Hexagon::A2_svsubuhs:
    case Hexagon::A4_andn:
    case Hexagon::A4_orn:
    case Hexagon::dep_A2_subsat: {
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vinsertwr: {
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::M2_subacc: {
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vdeal:
    case Hexagon::V6_vshuff: {
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vy32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vx32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::Y6_l2gcleaninvpa:
    case Hexagon::Y6_l2gcleanpa: {
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      break;
    }
    case Hexagon::S2_valignrb: {
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Pu4
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x3) << 5;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::A2_minp:
    case Hexagon::A2_minup:
    case Hexagon::A2_subp:
    case Hexagon::A2_vmaxb:
    case Hexagon::A2_vmaxh:
    case Hexagon::A2_vmaxub:
    case Hexagon::A2_vmaxuh:
    case Hexagon::A2_vmaxuw:
    case Hexagon::A2_vmaxw:
    case Hexagon::A2_vminb:
    case Hexagon::A2_vminh:
    case Hexagon::A2_vminub:
    case Hexagon::A2_vminuh:
    case Hexagon::A2_vminuw:
    case Hexagon::A2_vminw:
    case Hexagon::A2_vnavgh:
    case Hexagon::A2_vnavghcr:
    case Hexagon::A2_vnavghr:
    case Hexagon::A2_vnavgw:
    case Hexagon::A2_vnavgwcr:
    case Hexagon::A2_vnavgwr:
    case Hexagon::A2_vsubh:
    case Hexagon::A2_vsubhs:
    case Hexagon::A2_vsubub:
    case Hexagon::A2_vsububs:
    case Hexagon::A2_vsubuhs:
    case Hexagon::A2_vsubw:
    case Hexagon::A2_vsubws:
    case Hexagon::A4_andnp:
    case Hexagon::A4_ornp:
    case Hexagon::M2_vabsdiffh:
    case Hexagon::M2_vabsdiffw:
    case Hexagon::M6_vabsdiffb:
    case Hexagon::M6_vabsdiffub:
    case Hexagon::S2_shuffob:
    case Hexagon::S2_shuffoh: {
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::A6_vminub_RdP: {
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rss32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Pe4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 5;
      break;
    }
    case Hexagon::M4_mpyrr_addr: {
      // op: Ru32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Ry32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      break;
    }
    case Hexagon::Y2_crswap0:
    case Hexagon::Y4_crswap1: {
      // op: Rx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::Y4_crswap10: {
      // op: Rxx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::Y2_tfrscrr: {
      // op: Ss128
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::Y4_tfrscpp: {
      // op: Sss128
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7f) << 16;
      // op: Rdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_extractw: {
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rs32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Rd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vandvrt: {
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Qd4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      break;
    }
    case Hexagon::V6_get_qfext:
    case Hexagon::V6_set_qfext:
    case Hexagon::V6_vaslh:
    case Hexagon::V6_vaslw:
    case Hexagon::V6_vasrh:
    case Hexagon::V6_vasrw:
    case Hexagon::V6_vdmpybus:
    case Hexagon::V6_vdmpyhb:
    case Hexagon::V6_vdmpyhsat:
    case Hexagon::V6_vdmpyhsusat:
    case Hexagon::V6_vlsrb:
    case Hexagon::V6_vlsrh:
    case Hexagon::V6_vlsrw:
    case Hexagon::V6_vmpy_rt_hf:
    case Hexagon::V6_vmpy_rt_qf16:
    case Hexagon::V6_vmpy_rt_sf:
    case Hexagon::V6_vmpyhsrs:
    case Hexagon::V6_vmpyhss:
    case Hexagon::V6_vmpyihb:
    case Hexagon::V6_vmpyiwb:
    case Hexagon::V6_vmpyiwh:
    case Hexagon::V6_vmpyiwub:
    case Hexagon::V6_vmpyuhe:
    case Hexagon::V6_vrmpybus:
    case Hexagon::V6_vrmpyub:
    case Hexagon::V6_vror: {
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vmpybus:
    case Hexagon::V6_vmpyh:
    case Hexagon::V6_vmpyub:
    case Hexagon::V6_vmpyuh: {
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vrmpyzbb_rt:
    case Hexagon::V6_vrmpyzbub_rt:
    case Hexagon::V6_vrmpyzcb_rt:
    case Hexagon::V6_vrmpyzcbs_rt:
    case Hexagon::V6_vrmpyznb_rt: {
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rt8
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x7) << 16;
      // op: Vdddd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vlut4: {
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vrmpybub_rtt:
    case Hexagon::V6_vrmpyub_rtt: {
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vabs_f8:
    case Hexagon::V6_vabs_hf:
    case Hexagon::V6_vabs_qf16_hf:
    case Hexagon::V6_vabs_qf16_qf16:
    case Hexagon::V6_vabs_qf32_qf32:
    case Hexagon::V6_vabs_qf32_sf:
    case Hexagon::V6_vabs_sf:
    case Hexagon::V6_vabsb:
    case Hexagon::V6_vabsb_sat:
    case Hexagon::V6_vabsh:
    case Hexagon::V6_vabsh_sat:
    case Hexagon::V6_vabsw:
    case Hexagon::V6_vabsw_sat:
    case Hexagon::V6_vassign:
    case Hexagon::V6_vassign_fp:
    case Hexagon::V6_vassign_tmp:
    case Hexagon::V6_vcl0h:
    case Hexagon::V6_vcl0w:
    case Hexagon::V6_vconv_f8_qf16:
    case Hexagon::V6_vconv_h_hf:
    case Hexagon::V6_vconv_h_hf_rnd:
    case Hexagon::V6_vconv_hf_h:
    case Hexagon::V6_vconv_hf_qf16:
    case Hexagon::V6_vconv_qf16_hf:
    case Hexagon::V6_vconv_qf16_qf16:
    case Hexagon::V6_vconv_qf32_qf32:
    case Hexagon::V6_vconv_qf32_sf:
    case Hexagon::V6_vconv_sf_qf32:
    case Hexagon::V6_vconv_sf_w:
    case Hexagon::V6_vconv_w_sf:
    case Hexagon::V6_vcvt_h_hf:
    case Hexagon::V6_vcvt_hf_h:
    case Hexagon::V6_vcvt_hf_uh:
    case Hexagon::V6_vcvt_uh_hf:
    case Hexagon::V6_vdealb:
    case Hexagon::V6_vdealh:
    case Hexagon::V6_vfneg_f8:
    case Hexagon::V6_vfneg_hf:
    case Hexagon::V6_vfneg_sf:
    case Hexagon::V6_vilog2_hf:
    case Hexagon::V6_vilog2_qf16:
    case Hexagon::V6_vilog2_qf32:
    case Hexagon::V6_vilog2_sf:
    case Hexagon::V6_vneg_qf16_hf:
    case Hexagon::V6_vneg_qf16_qf16:
    case Hexagon::V6_vneg_qf32_qf32:
    case Hexagon::V6_vneg_qf32_sf:
    case Hexagon::V6_vnormamth:
    case Hexagon::V6_vnormamtw:
    case Hexagon::V6_vnot:
    case Hexagon::V6_vpopcounth:
    case Hexagon::V6_vshuffb:
    case Hexagon::V6_vshuffh: {
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vconv_qf16_f8:
    case Hexagon::V6_vcvt2_hf_b:
    case Hexagon::V6_vcvt2_hf_ub:
    case Hexagon::V6_vcvt_hf_b:
    case Hexagon::V6_vcvt_hf_f8:
    case Hexagon::V6_vcvt_hf_ub:
    case Hexagon::V6_vcvt_sf_hf:
    case Hexagon::V6_vsb:
    case Hexagon::V6_vsh:
    case Hexagon::V6_vunpackb:
    case Hexagon::V6_vunpackh:
    case Hexagon::V6_vunpackub:
    case Hexagon::V6_vunpackuh:
    case Hexagon::V6_vzb:
    case Hexagon::V6_vzh: {
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_veqb:
    case Hexagon::V6_veqh:
    case Hexagon::V6_veqhf:
    case Hexagon::V6_veqsf:
    case Hexagon::V6_veqw:
    case Hexagon::V6_vgtb:
    case Hexagon::V6_vgtbf:
    case Hexagon::V6_vgth:
    case Hexagon::V6_vgthf:
    case Hexagon::V6_vgtsf:
    case Hexagon::V6_vgtub:
    case Hexagon::V6_vgtuh:
    case Hexagon::V6_vgtuw:
    case Hexagon::V6_vgtw: {
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vv32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Qd4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      break;
    }
    case Hexagon::V6_vaddcarrysat: {
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vv32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Qs4
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x3) << 5;
      // op: Vd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vabsdiffh:
    case Hexagon::V6_vabsdiffub:
    case Hexagon::V6_vabsdiffuh:
    case Hexagon::V6_vabsdiffw:
    case Hexagon::V6_vadd_hf:
    case Hexagon::V6_vadd_hf_hf:
    case Hexagon::V6_vadd_qf16:
    case Hexagon::V6_vadd_qf16_mix:
    case Hexagon::V6_vadd_qf32:
    case Hexagon::V6_vadd_qf32_mix:
    case Hexagon::V6_vadd_sf:
    case Hexagon::V6_vadd_sf_sf:
    case Hexagon::V6_vaddb:
    case Hexagon::V6_vaddbsat:
    case Hexagon::V6_vaddclbh:
    case Hexagon::V6_vaddclbw:
    case Hexagon::V6_vaddh:
    case Hexagon::V6_vaddhsat:
    case Hexagon::V6_vaddubsat:
    case Hexagon::V6_vaddububb_sat:
    case Hexagon::V6_vadduhsat:
    case Hexagon::V6_vadduwsat:
    case Hexagon::V6_vaddw:
    case Hexagon::V6_vaddwsat:
    case Hexagon::V6_vand:
    case Hexagon::V6_vaslhv:
    case Hexagon::V6_vaslwv:
    case Hexagon::V6_vasrhv:
    case Hexagon::V6_vasrwv:
    case Hexagon::V6_vavgb:
    case Hexagon::V6_vavgbrnd:
    case Hexagon::V6_vavgh:
    case Hexagon::V6_vavghrnd:
    case Hexagon::V6_vavgub:
    case Hexagon::V6_vavgubrnd:
    case Hexagon::V6_vavguh:
    case Hexagon::V6_vavguhrnd:
    case Hexagon::V6_vavguw:
    case Hexagon::V6_vavguwrnd:
    case Hexagon::V6_vavgw:
    case Hexagon::V6_vavgwrnd:
    case Hexagon::V6_vcvt2_b_hf:
    case Hexagon::V6_vcvt2_ub_hf:
    case Hexagon::V6_vcvt_b_hf:
    case Hexagon::V6_vcvt_bf_sf:
    case Hexagon::V6_vcvt_f8_hf:
    case Hexagon::V6_vcvt_hf_sf:
    case Hexagon::V6_vcvt_ub_hf:
    case Hexagon::V6_vdealb4w:
    case Hexagon::V6_vdelta:
    case Hexagon::V6_vdmpy_sf_hf:
    case Hexagon::V6_vdmpyhvsat:
    case Hexagon::V6_vfmax_f8:
    case Hexagon::V6_vfmax_hf:
    case Hexagon::V6_vfmax_sf:
    case Hexagon::V6_vfmin_f8:
    case Hexagon::V6_vfmin_hf:
    case Hexagon::V6_vfmin_sf:
    case Hexagon::V6_vlsrhv:
    case Hexagon::V6_vlsrwv:
    case Hexagon::V6_vmax_bf:
    case Hexagon::V6_vmax_hf:
    case Hexagon::V6_vmax_sf:
    case Hexagon::V6_vmaxb:
    case Hexagon::V6_vmaxh:
    case Hexagon::V6_vmaxub:
    case Hexagon::V6_vmaxuh:
    case Hexagon::V6_vmaxw:
    case Hexagon::V6_vmerge_qf:
    case Hexagon::V6_vmin_bf:
    case Hexagon::V6_vmin_hf:
    case Hexagon::V6_vmin_sf:
    case Hexagon::V6_vminb:
    case Hexagon::V6_vminh:
    case Hexagon::V6_vminub:
    case Hexagon::V6_vminuh:
    case Hexagon::V6_vminw:
    case Hexagon::V6_vmpy_hf_hf:
    case Hexagon::V6_vmpy_qf16:
    case Hexagon::V6_vmpy_qf16_hf:
    case Hexagon::V6_vmpy_qf16_mix_hf:
    case Hexagon::V6_vmpy_qf32:
    case Hexagon::V6_vmpy_qf32_sf:
    case Hexagon::V6_vmpy_sf_sf:
    case Hexagon::V6_vmpyewuh:
    case Hexagon::V6_vmpyhvsrs:
    case Hexagon::V6_vmpyieoh:
    case Hexagon::V6_vmpyiewuh:
    case Hexagon::V6_vmpyih:
    case Hexagon::V6_vmpyiowh:
    case Hexagon::V6_vmpyowh:
    case Hexagon::V6_vmpyowh_rnd:
    case Hexagon::V6_vmpyuhvs:
    case Hexagon::V6_vnavgb:
    case Hexagon::V6_vnavgh:
    case Hexagon::V6_vnavgub:
    case Hexagon::V6_vnavgw:
    case Hexagon::V6_vor:
    case Hexagon::V6_vpackeb:
    case Hexagon::V6_vpackeh:
    case Hexagon::V6_vpackhb_sat:
    case Hexagon::V6_vpackhub_sat:
    case Hexagon::V6_vpackob:
    case Hexagon::V6_vpackoh:
    case Hexagon::V6_vpackwh_sat:
    case Hexagon::V6_vpackwuh_sat:
    case Hexagon::V6_vrdelta:
    case Hexagon::V6_vrmpybusv:
    case Hexagon::V6_vrmpybv:
    case Hexagon::V6_vrmpyubv:
    case Hexagon::V6_vrotr:
    case Hexagon::V6_vroundhb:
    case Hexagon::V6_vroundhub:
    case Hexagon::V6_vrounduhub:
    case Hexagon::V6_vrounduwuh:
    case Hexagon::V6_vroundwh:
    case Hexagon::V6_vroundwuh:
    case Hexagon::V6_vsatdw:
    case Hexagon::V6_vsathub:
    case Hexagon::V6_vsatuwuh:
    case Hexagon::V6_vsatwh:
    case Hexagon::V6_vshufeh:
    case Hexagon::V6_vshuffeb:
    case Hexagon::V6_vshuffob:
    case Hexagon::V6_vshufoh:
    case Hexagon::V6_vsub_hf:
    case Hexagon::V6_vsub_hf_hf:
    case Hexagon::V6_vsub_hf_mix:
    case Hexagon::V6_vsub_qf16:
    case Hexagon::V6_vsub_qf16_mix:
    case Hexagon::V6_vsub_qf32:
    case Hexagon::V6_vsub_qf32_mix:
    case Hexagon::V6_vsub_sf:
    case Hexagon::V6_vsub_sf_mix:
    case Hexagon::V6_vsub_sf_sf:
    case Hexagon::V6_vsubb:
    case Hexagon::V6_vsubbsat:
    case Hexagon::V6_vsubh:
    case Hexagon::V6_vsubhsat:
    case Hexagon::V6_vsububsat:
    case Hexagon::V6_vsubububb_sat:
    case Hexagon::V6_vsubuhsat:
    case Hexagon::V6_vsubuwsat:
    case Hexagon::V6_vsubw:
    case Hexagon::V6_vsubwsat:
    case Hexagon::V6_vxor: {
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vv32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vadd_hf_f8:
    case Hexagon::V6_vadd_sf_bf:
    case Hexagon::V6_vadd_sf_hf:
    case Hexagon::V6_vaddhw:
    case Hexagon::V6_vaddubh:
    case Hexagon::V6_vadduhw:
    case Hexagon::V6_vcombine:
    case Hexagon::V6_vcombine_tmp:
    case Hexagon::V6_vmpy_hf_f8:
    case Hexagon::V6_vmpy_qf32_hf:
    case Hexagon::V6_vmpy_qf32_mix_hf:
    case Hexagon::V6_vmpy_qf32_qf16:
    case Hexagon::V6_vmpy_sf_bf:
    case Hexagon::V6_vmpy_sf_hf:
    case Hexagon::V6_vmpybusv:
    case Hexagon::V6_vmpybv:
    case Hexagon::V6_vmpyewuh_64:
    case Hexagon::V6_vmpyhus:
    case Hexagon::V6_vmpyhv:
    case Hexagon::V6_vmpyubv:
    case Hexagon::V6_vmpyuhv:
    case Hexagon::V6_vshufoeb:
    case Hexagon::V6_vshufoeh:
    case Hexagon::V6_vsub_hf_f8:
    case Hexagon::V6_vsub_sf_bf:
    case Hexagon::V6_vsub_sf_hf:
    case Hexagon::V6_vsubhw:
    case Hexagon::V6_vsububh:
    case Hexagon::V6_vsubuhw: {
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vv32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_valign4:
    case Hexagon::V6_valignb:
    case Hexagon::V6_vasrhbrndsat:
    case Hexagon::V6_vasrhbsat:
    case Hexagon::V6_vasrhubrndsat:
    case Hexagon::V6_vasrhubsat:
    case Hexagon::V6_vasruhubrndsat:
    case Hexagon::V6_vasruhubsat:
    case Hexagon::V6_vasruwuhrndsat:
    case Hexagon::V6_vasruwuhsat:
    case Hexagon::V6_vasrwh:
    case Hexagon::V6_vasrwhrndsat:
    case Hexagon::V6_vasrwhsat:
    case Hexagon::V6_vasrwuhrndsat:
    case Hexagon::V6_vasrwuhsat:
    case Hexagon::V6_vlalignb:
    case Hexagon::V6_vlutvvb:
    case Hexagon::V6_vlutvvb_nm: {
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vv32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 19;
      // op: Rt8
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x7) << 16;
      // op: Vd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vdealvdd:
    case Hexagon::V6_vlutvwh:
    case Hexagon::V6_vlutvwh_nm:
    case Hexagon::V6_vshuffvdd: {
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vv32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 19;
      // op: Rt8
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x7) << 16;
      // op: Vdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vandvrt_acc: {
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Qx4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      break;
    }
    case Hexagon::V6_get_qfext_oracc:
    case Hexagon::V6_vaslh_acc:
    case Hexagon::V6_vaslw_acc:
    case Hexagon::V6_vasrh_acc:
    case Hexagon::V6_vasrw_acc:
    case Hexagon::V6_vdmpybus_acc:
    case Hexagon::V6_vdmpyhb_acc:
    case Hexagon::V6_vdmpyhsat_acc:
    case Hexagon::V6_vdmpyhsusat_acc:
    case Hexagon::V6_vmpyihb_acc:
    case Hexagon::V6_vmpyiwb_acc:
    case Hexagon::V6_vmpyiwh_acc:
    case Hexagon::V6_vmpyiwub_acc:
    case Hexagon::V6_vmpyuhe_acc:
    case Hexagon::V6_vrmpybus_acc:
    case Hexagon::V6_vrmpyub_acc: {
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vmpybus_acc:
    case Hexagon::V6_vmpyh_acc:
    case Hexagon::V6_vmpyhsat_acc:
    case Hexagon::V6_vmpyub_acc:
    case Hexagon::V6_vmpyuh_acc: {
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vxx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vrmpyzbb_rt_acc:
    case Hexagon::V6_vrmpyzbub_rt_acc:
    case Hexagon::V6_vrmpyzcb_rt_acc:
    case Hexagon::V6_vrmpyzcbs_rt_acc:
    case Hexagon::V6_vrmpyznb_rt_acc: {
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rt8
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x7) << 16;
      // op: Vyyyy32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vmpahhsat:
    case Hexagon::V6_vmpauhuhsat:
    case Hexagon::V6_vmpsuhuhsat: {
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vrmpybub_rtt_acc:
    case Hexagon::V6_vrmpyub_rtt_acc: {
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rtt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vxx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vrmpyzbb_rx:
    case Hexagon::V6_vrmpyzbub_rx:
    case Hexagon::V6_vrmpyzcb_rx:
    case Hexagon::V6_vrmpyzcbs_rx:
    case Hexagon::V6_vrmpyznb_rx: {
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vdddd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx8
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7) << 16;
      break;
    }
    case Hexagon::V6_veqb_and:
    case Hexagon::V6_veqb_or:
    case Hexagon::V6_veqb_xor:
    case Hexagon::V6_veqh_and:
    case Hexagon::V6_veqh_or:
    case Hexagon::V6_veqh_xor:
    case Hexagon::V6_veqhf_and:
    case Hexagon::V6_veqhf_or:
    case Hexagon::V6_veqhf_xor:
    case Hexagon::V6_veqsf_and:
    case Hexagon::V6_veqsf_or:
    case Hexagon::V6_veqsf_xor:
    case Hexagon::V6_veqw_and:
    case Hexagon::V6_veqw_or:
    case Hexagon::V6_veqw_xor:
    case Hexagon::V6_vgtb_and:
    case Hexagon::V6_vgtb_or:
    case Hexagon::V6_vgtb_xor:
    case Hexagon::V6_vgtbf_and:
    case Hexagon::V6_vgtbf_or:
    case Hexagon::V6_vgtbf_xor:
    case Hexagon::V6_vgth_and:
    case Hexagon::V6_vgth_or:
    case Hexagon::V6_vgth_xor:
    case Hexagon::V6_vgthf_and:
    case Hexagon::V6_vgthf_or:
    case Hexagon::V6_vgthf_xor:
    case Hexagon::V6_vgtsf_and:
    case Hexagon::V6_vgtsf_or:
    case Hexagon::V6_vgtsf_xor:
    case Hexagon::V6_vgtub_and:
    case Hexagon::V6_vgtub_or:
    case Hexagon::V6_vgtub_xor:
    case Hexagon::V6_vgtuh_and:
    case Hexagon::V6_vgtuh_or:
    case Hexagon::V6_vgtuh_xor:
    case Hexagon::V6_vgtuw_and:
    case Hexagon::V6_vgtuw_or:
    case Hexagon::V6_vgtuw_xor:
    case Hexagon::V6_vgtw_and:
    case Hexagon::V6_vgtw_or:
    case Hexagon::V6_vgtw_xor: {
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vv32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Qx4
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3);
      break;
    }
    case Hexagon::V6_vaddcarryo:
    case Hexagon::V6_vsubcarryo: {
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vv32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Qe4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 5;
      break;
    }
    case Hexagon::V6_vaddcarry:
    case Hexagon::V6_vsubcarry: {
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vv32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Qx4
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3) << 5;
      break;
    }
    case Hexagon::V6_vdmpy_sf_hf_acc:
    case Hexagon::V6_vdmpyhvsat_acc:
    case Hexagon::V6_vmpy_hf_hf_acc:
    case Hexagon::V6_vmpyiewh_acc:
    case Hexagon::V6_vmpyiewuh_acc:
    case Hexagon::V6_vmpyih_acc:
    case Hexagon::V6_vmpyowh_rnd_sacc:
    case Hexagon::V6_vmpyowh_sacc:
    case Hexagon::V6_vrmpybusv_acc:
    case Hexagon::V6_vrmpybv_acc:
    case Hexagon::V6_vrmpyubv_acc: {
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vv32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vaddhw_acc:
    case Hexagon::V6_vaddubh_acc:
    case Hexagon::V6_vadduhw_acc:
    case Hexagon::V6_vasr_into:
    case Hexagon::V6_vmpy_hf_f8_acc:
    case Hexagon::V6_vmpy_sf_bf_acc:
    case Hexagon::V6_vmpy_sf_hf_acc:
    case Hexagon::V6_vmpybusv_acc:
    case Hexagon::V6_vmpybv_acc:
    case Hexagon::V6_vmpyhus_acc:
    case Hexagon::V6_vmpyhv_acc:
    case Hexagon::V6_vmpyowh_64_acc:
    case Hexagon::V6_vmpyubv_acc:
    case Hexagon::V6_vmpyuhv_acc: {
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vv32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vxx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vlutvvb_oracc: {
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vv32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 19;
      // op: Rt8
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x7) << 16;
      // op: Vx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vlutvwh_oracc: {
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vv32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 19;
      // op: Rt8
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & 0x7) << 16;
      // op: Vxx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vunpackob:
    case Hexagon::V6_vunpackoh: {
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vxx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vrmpyzbb_rx_acc:
    case Hexagon::V6_vrmpyzbub_rx_acc:
    case Hexagon::V6_vrmpyzcb_rx_acc:
    case Hexagon::V6_vrmpyzcbs_rx_acc:
    case Hexagon::V6_vrmpyznb_rx_acc: {
      // op: Vu32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vyyyy32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      // op: Rx8
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x7) << 16;
      break;
    }
    case Hexagon::V6_vdmpyhisat:
    case Hexagon::V6_vdmpyhsuisat: {
      // op: Vuu32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vdmpybus_dv:
    case Hexagon::V6_vdmpyhb_dv:
    case Hexagon::V6_vdsaduh:
    case Hexagon::V6_vmpabus:
    case Hexagon::V6_vmpabuu:
    case Hexagon::V6_vmpahb:
    case Hexagon::V6_vmpauhb:
    case Hexagon::V6_vtmpyb:
    case Hexagon::V6_vtmpybus:
    case Hexagon::V6_vtmpyhb: {
      // op: Vuu32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vconv_bf_qf32:
    case Hexagon::V6_vconv_hf_qf32: {
      // op: Vuu32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vasrvuhubrndsat:
    case Hexagon::V6_vasrvuhubsat:
    case Hexagon::V6_vasrvwuhrndsat:
    case Hexagon::V6_vasrvwuhsat: {
      // op: Vuu32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vv32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vaddb_dv:
    case Hexagon::V6_vaddbsat_dv:
    case Hexagon::V6_vaddh_dv:
    case Hexagon::V6_vaddhsat_dv:
    case Hexagon::V6_vaddubsat_dv:
    case Hexagon::V6_vadduhsat_dv:
    case Hexagon::V6_vadduwsat_dv:
    case Hexagon::V6_vaddw_dv:
    case Hexagon::V6_vaddwsat_dv:
    case Hexagon::V6_vmpabusv:
    case Hexagon::V6_vmpabuuv:
    case Hexagon::V6_vsubb_dv:
    case Hexagon::V6_vsubbsat_dv:
    case Hexagon::V6_vsubh_dv:
    case Hexagon::V6_vsubhsat_dv:
    case Hexagon::V6_vsububsat_dv:
    case Hexagon::V6_vsubuhsat_dv:
    case Hexagon::V6_vsubuwsat_dv:
    case Hexagon::V6_vsubw_dv:
    case Hexagon::V6_vsubwsat_dv: {
      // op: Vuu32
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Vvv32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vdd32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vdmpyhisat_acc:
    case Hexagon::V6_vdmpyhsuisat_acc: {
      // op: Vuu32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::V6_vdmpybus_dv_acc:
    case Hexagon::V6_vdmpyhb_dv_acc:
    case Hexagon::V6_vdsaduh_acc:
    case Hexagon::V6_vmpabus_acc:
    case Hexagon::V6_vmpabuu_acc:
    case Hexagon::V6_vmpahb_acc:
    case Hexagon::V6_vmpauhb_acc:
    case Hexagon::V6_vtmpyb_acc:
    case Hexagon::V6_vtmpybus_acc:
    case Hexagon::V6_vtmpyhb_acc: {
      // op: Vuu32
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & 0x1f) << 8;
      // op: Rt32
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: Vxx32
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f);
      break;
    }
    case Hexagon::EH_RETURN_JMPR:
    case Hexagon::PS_jmpret: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::HI:
    case Hexagon::LO: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      // op: imm_value
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0xc000) << 8;
      Value |= (op & 0x3fff);
      break;
    }
    case Hexagon::CALLProfile:
    case Hexagon::PS_call_stk:
    case Hexagon::RESTORE_DEALLOC_BEFORE_TAILCALL_V4:
    case Hexagon::RESTORE_DEALLOC_BEFORE_TAILCALL_V4_EXT:
    case Hexagon::RESTORE_DEALLOC_BEFORE_TAILCALL_V4_EXT_PIC:
    case Hexagon::RESTORE_DEALLOC_BEFORE_TAILCALL_V4_PIC:
    case Hexagon::RESTORE_DEALLOC_RET_JMP_V4:
    case Hexagon::RESTORE_DEALLOC_RET_JMP_V4_EXT:
    case Hexagon::RESTORE_DEALLOC_RET_JMP_V4_EXT_PIC:
    case Hexagon::RESTORE_DEALLOC_RET_JMP_V4_PIC:
    case Hexagon::SAVE_REGISTERS_CALL_V4:
    case Hexagon::SAVE_REGISTERS_CALL_V4STK:
    case Hexagon::SAVE_REGISTERS_CALL_V4STK_EXT:
    case Hexagon::SAVE_REGISTERS_CALL_V4STK_EXT_PIC:
    case Hexagon::SAVE_REGISTERS_CALL_V4STK_PIC:
    case Hexagon::SAVE_REGISTERS_CALL_V4_EXT:
    case Hexagon::SAVE_REGISTERS_CALL_V4_EXT_PIC:
    case Hexagon::SAVE_REGISTERS_CALL_V4_PIC: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0xff8000) << 1;
      Value |= (op & 0x7ffc) >> 1;
      break;
    }
    case Hexagon::J2_loop0rext:
    case Hexagon::J2_loop1rext: {
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f0) << 4;
      Value |= (op & 0xc) << 1;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
    case Hexagon::J2_loop0iext:
    case Hexagon::J2_loop1iext: {
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x1f0) << 4;
      Value |= (op & 0xc) << 1;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x3e0) << 11;
      Value |= (op & 0x1c) << 3;
      Value |= (op & 0x3);
      break;
    }
    case Hexagon::PS_jmpretf:
    case Hexagon::PS_jmpretfnew:
    case Hexagon::PS_jmpretfnewpt:
    case Hexagon::PS_jmprett:
    case Hexagon::PS_jmprettnew:
    case Hexagon::PS_jmprettnewpt: {
      // op: src
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & 0x3) << 8;
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & 0x1f) << 16;
      break;
    }
  default:
    reportUnsupportedInst(MI);
  }
  return Value;
}

#ifdef GET_OPERAND_BIT_OFFSET
#undef GET_OPERAND_BIT_OFFSET

uint32_t HexagonMCCodeEmitter::getOperandBitOffset(const MCInst &MI,
    unsigned OpNum,
    const MCSubtargetInfo &STI) const {
  switch (MI.getOpcode()) {
    case Hexagon::A2_nop:
    case Hexagon::CONST32:
    case Hexagon::CONST64:
    case Hexagon::DuplexIClass0:
    case Hexagon::DuplexIClass1:
    case Hexagon::DuplexIClass2:
    case Hexagon::DuplexIClass3:
    case Hexagon::DuplexIClass4:
    case Hexagon::DuplexIClass5:
    case Hexagon::DuplexIClass6:
    case Hexagon::DuplexIClass7:
    case Hexagon::DuplexIClass8:
    case Hexagon::DuplexIClass9:
    case Hexagon::DuplexIClassA:
    case Hexagon::DuplexIClassB:
    case Hexagon::DuplexIClassC:
    case Hexagon::DuplexIClassD:
    case Hexagon::DuplexIClassE:
    case Hexagon::DuplexIClassF:
    case Hexagon::J2_rte:
    case Hexagon::J2_unpause:
    case Hexagon::SL2_deallocframe:
    case Hexagon::SL2_jumpr31:
    case Hexagon::SL2_jumpr31_f:
    case Hexagon::SL2_jumpr31_fnew:
    case Hexagon::SL2_jumpr31_t:
    case Hexagon::SL2_jumpr31_tnew:
    case Hexagon::SL2_return:
    case Hexagon::SL2_return_f:
    case Hexagon::SL2_return_fnew:
    case Hexagon::SL2_return_t:
    case Hexagon::SL2_return_tnew:
    case Hexagon::TFRI64_V2_ext:
    case Hexagon::TFRI64_V4:
    case Hexagon::V6_vhist:
    case Hexagon::V6_vwhist128:
    case Hexagon::V6_vwhist256:
    case Hexagon::V6_vwhist256_sat:
    case Hexagon::Y2_barrier:
    case Hexagon::Y2_break:
    case Hexagon::Y2_dckill:
    case Hexagon::Y2_ickill:
    case Hexagon::Y2_isync:
    case Hexagon::Y2_k0lock:
    case Hexagon::Y2_k0unlock:
    case Hexagon::Y2_l2kill:
    case Hexagon::Y2_syncht:
    case Hexagon::Y2_tlblock:
    case Hexagon::Y2_tlbunlock:
    case Hexagon::Y5_l2gclean:
    case Hexagon::Y5_l2gcleaninv:
    case Hexagon::Y5_l2gunlock:
    case Hexagon::invalid_decode: {
      break;
    }
    case Hexagon::PS_storerbnewabs:
    case Hexagon::PS_storerhnewabs:
    case Hexagon::PS_storerinewabs:
    case Hexagon::S2_storerbnewgp:
    case Hexagon::S2_storerhnewgp:
    case Hexagon::S2_storerinewgp: {
      switch (OpNum) {
      case 0:
        // op: Ii
        return 0;
      case 1:
        // op: Nt8
        return 8;
      }
      break;
    }
    case Hexagon::PS_storerbabs:
    case Hexagon::PS_storerfabs:
    case Hexagon::PS_storerhabs:
    case Hexagon::PS_storeriabs:
    case Hexagon::S2_storerbgp:
    case Hexagon::S2_storerfgp:
    case Hexagon::S2_storerhgp:
    case Hexagon::S2_storerigp: {
      switch (OpNum) {
      case 0:
        // op: Ii
        return 0;
      case 1:
        // op: Rt32
        return 8;
      }
      break;
    }
    case Hexagon::PS_storerdabs:
    case Hexagon::S2_storerdgp: {
      switch (OpNum) {
      case 0:
        // op: Ii
        return 0;
      case 1:
        // op: Rtt32
        return 8;
      }
      break;
    }
    case Hexagon::A4_ext: {
      switch (OpNum) {
      case 0:
        // op: Ii
        return 0;
      }
      break;
    }
    case Hexagon::J2_call:
    case Hexagon::J2_jump: {
      switch (OpNum) {
      case 0:
        // op: Ii
        return 1;
      }
      break;
    }
    case Hexagon::J2_pause:
    case Hexagon::J2_trap0:
    case Hexagon::PS_trap1: {
      switch (OpNum) {
      case 0:
        // op: Ii
        return 2;
      }
      break;
    }
    case Hexagon::J2_loop0i:
    case Hexagon::J2_loop1i:
    case Hexagon::J2_ploop1si:
    case Hexagon::J2_ploop2si:
    case Hexagon::J2_ploop3si: {
      switch (OpNum) {
      case 0:
        // op: Ii
        return 3;
      case 1:
        // op: II
        return 0;
      }
      break;
    }
    case Hexagon::J2_loop0r:
    case Hexagon::J2_loop1r:
    case Hexagon::J2_ploop1sr:
    case Hexagon::J2_ploop2sr:
    case Hexagon::J2_ploop3sr: {
      switch (OpNum) {
      case 0:
        // op: Ii
        return 3;
      case 1:
        // op: Rs32
        return 16;
      }
      break;
    }
    case Hexagon::SS2_stored_sp: {
      switch (OpNum) {
      case 0:
        // op: Ii
        return 3;
      case 1:
        // op: Rtt8
        return 0;
      }
      break;
    }
    case Hexagon::SS2_storew_sp: {
      switch (OpNum) {
      case 0:
        // op: Ii
        return 4;
      case 1:
        // op: Rt16
        return 0;
      }
      break;
    }
    case Hexagon::SS2_allocframe: {
      switch (OpNum) {
      case 0:
        // op: Ii
        return 4;
      }
      break;
    }
    case Hexagon::V6_vwhist128m: {
      switch (OpNum) {
      case 0:
        // op: Ii
        return 8;
      }
      break;
    }
    case Hexagon::Y2_setimask:
    case Hexagon::Y2_setprio: {
      switch (OpNum) {
      case 0:
        // op: Pt4
        return 8;
      case 1:
        // op: Rs32
        return 16;
      }
      break;
    }
    case Hexagon::J2_callrf:
    case Hexagon::J2_callrt:
    case Hexagon::J2_jumprf:
    case Hexagon::J2_jumprfnew:
    case Hexagon::J2_jumprfnewpt:
    case Hexagon::J2_jumprfpt:
    case Hexagon::J2_jumprt:
    case Hexagon::J2_jumprtnew:
    case Hexagon::J2_jumprtnewpt:
    case Hexagon::J2_jumprtpt: {
      switch (OpNum) {
      case 0:
        // op: Pu4
        return 8;
      case 1:
        // op: Rs32
        return 16;
      }
      break;
    }
    case Hexagon::V6_vgathermhq:
    case Hexagon::V6_vgathermwq: {
      switch (OpNum) {
      case 0:
        // op: Qs4
        return 5;
      case 1:
        // op: Rt32
        return 16;
      case 2:
        // op: Mu2
        return 13;
      case 3:
        // op: Vv32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vscattermhq:
    case Hexagon::V6_vscattermwq: {
      switch (OpNum) {
      case 0:
        // op: Qs4
        return 5;
      case 1:
        // op: Rt32
        return 16;
      case 2:
        // op: Mu2
        return 13;
      case 3:
        // op: Vv32
        return 8;
      case 4:
        // op: Vw32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vgathermhwq: {
      switch (OpNum) {
      case 0:
        // op: Qs4
        return 5;
      case 1:
        // op: Rt32
        return 16;
      case 2:
        // op: Mu2
        return 13;
      case 3:
        // op: Vvv32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vscattermhwq: {
      switch (OpNum) {
      case 0:
        // op: Qs4
        return 5;
      case 1:
        // op: Rt32
        return 16;
      case 2:
        // op: Mu2
        return 13;
      case 3:
        // op: Vvv32
        return 8;
      case 4:
        // op: Vw32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vhistq:
    case Hexagon::V6_vwhist128q:
    case Hexagon::V6_vwhist256q:
    case Hexagon::V6_vwhist256q_sat: {
      switch (OpNum) {
      case 0:
        // op: Qv4
        return 22;
      }
      break;
    }
    case Hexagon::SA1_clrf:
    case Hexagon::SA1_clrfnew:
    case Hexagon::SA1_clrt:
    case Hexagon::SA1_clrtnew:
    case Hexagon::SA1_setin1: {
      switch (OpNum) {
      case 0:
        // op: Rd16
        return 0;
      }
      break;
    }
    case Hexagon::Y6_dmpause:
    case Hexagon::Y6_dmpoll:
    case Hexagon::Y6_dmwait: {
      switch (OpNum) {
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::PS_callr_nr: {
      switch (OpNum) {
      case 0:
        // op: Rs
        return 16;
      }
      break;
    }
    case Hexagon::L6_memcpy: {
      switch (OpNum) {
      case 0:
        // op: Rs32
        return 16;
      case 1:
        // op: Rt32
        return 8;
      case 2:
        // op: Mu2
        return 13;
      }
      break;
    }
    case Hexagon::S2_storew_rl_at_vi:
    case Hexagon::S2_storew_rl_st_vi:
    case Hexagon::Y2_dctagw:
    case Hexagon::Y2_icdataw:
    case Hexagon::Y2_ictagw:
    case Hexagon::Y4_l2fetch:
    case Hexagon::Y4_l2tagw:
    case Hexagon::Y6_dmlink: {
      switch (OpNum) {
      case 0:
        // op: Rs32
        return 16;
      case 1:
        // op: Rt32
        return 8;
      }
      break;
    }
    case Hexagon::S4_stored_rl_at_vi:
    case Hexagon::S4_stored_rl_st_vi:
    case Hexagon::Y5_l2fetch: {
      switch (OpNum) {
      case 0:
        // op: Rs32
        return 16;
      case 1:
        // op: Rtt32
        return 8;
      }
      break;
    }
    case Hexagon::J2_callr:
    case Hexagon::J2_callrh:
    case Hexagon::J2_jumpr:
    case Hexagon::J2_jumprh:
    case Hexagon::J4_hintjumpr:
    case Hexagon::R6_release_at_vi:
    case Hexagon::R6_release_st_vi:
    case Hexagon::Y2_ciad:
    case Hexagon::Y2_cswi:
    case Hexagon::Y2_dccleana:
    case Hexagon::Y2_dccleanidx:
    case Hexagon::Y2_dccleaninva:
    case Hexagon::Y2_dccleaninvidx:
    case Hexagon::Y2_dcinva:
    case Hexagon::Y2_dcinvidx:
    case Hexagon::Y2_dczeroa:
    case Hexagon::Y2_iassignw:
    case Hexagon::Y2_icinva:
    case Hexagon::Y2_icinvidx:
    case Hexagon::Y2_l2cleaninvidx:
    case Hexagon::Y2_resume:
    case Hexagon::Y2_start:
    case Hexagon::Y2_stop:
    case Hexagon::Y2_swi:
    case Hexagon::Y2_wait:
    case Hexagon::Y4_nmi:
    case Hexagon::Y4_siad:
    case Hexagon::Y4_trace:
    case Hexagon::Y5_l2cleanidx:
    case Hexagon::Y5_l2invidx:
    case Hexagon::Y5_l2unlocka:
    case Hexagon::Y5_tlbasidi:
    case Hexagon::Y6_diag:
    case Hexagon::Y6_dmresume:
    case Hexagon::Y6_dmstart: {
      switch (OpNum) {
      case 0:
        // op: Rs32
        return 16;
      }
      break;
    }
    case Hexagon::Y2_tlbw: {
      switch (OpNum) {
      case 0:
        // op: Rss32
        return 16;
      case 1:
        // op: Rt32
        return 8;
      }
      break;
    }
    case Hexagon::Y6_diag0:
    case Hexagon::Y6_diag1: {
      switch (OpNum) {
      case 0:
        // op: Rss32
        return 16;
      case 1:
        // op: Rtt32
        return 8;
      }
      break;
    }
    case Hexagon::V6_vgathermh:
    case Hexagon::V6_vgathermw: {
      switch (OpNum) {
      case 0:
        // op: Rt32
        return 16;
      case 1:
        // op: Mu2
        return 13;
      case 2:
        // op: Vv32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vscattermh:
    case Hexagon::V6_vscattermh_add:
    case Hexagon::V6_vscattermw:
    case Hexagon::V6_vscattermw_add: {
      switch (OpNum) {
      case 0:
        // op: Rt32
        return 16;
      case 1:
        // op: Mu2
        return 13;
      case 2:
        // op: Vv32
        return 8;
      case 3:
        // op: Vw32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vgathermhw: {
      switch (OpNum) {
      case 0:
        // op: Rt32
        return 16;
      case 1:
        // op: Mu2
        return 13;
      case 2:
        // op: Vvv32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vscattermhw:
    case Hexagon::V6_vscattermhw_add: {
      switch (OpNum) {
      case 0:
        // op: Rt32
        return 16;
      case 1:
        // op: Mu2
        return 13;
      case 2:
        // op: Vvv32
        return 8;
      case 3:
        // op: Vw32
        return 0;
      }
      break;
    }
    case Hexagon::Y6_l2gcleaninvpa:
    case Hexagon::Y6_l2gcleanpa: {
      switch (OpNum) {
      case 0:
        // op: Rtt32
        return 8;
      }
      break;
    }
    case Hexagon::Y2_crswap0:
    case Hexagon::Y4_crswap1: {
      switch (OpNum) {
      case 0:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::Y4_crswap10: {
      switch (OpNum) {
      case 0:
        // op: Rxx32
        return 16;
      }
      break;
    }
    case Hexagon::HI:
    case Hexagon::LO: {
      switch (OpNum) {
      case 0:
        // op: dst
        return 16;
      case 1:
        // op: imm_value
        return 0;
      }
      break;
    }
    case Hexagon::EH_RETURN_JMPR:
    case Hexagon::PS_jmpret: {
      switch (OpNum) {
      case 0:
        // op: dst
        return 16;
      }
      break;
    }
    case Hexagon::CALLProfile:
    case Hexagon::PS_call_stk:
    case Hexagon::RESTORE_DEALLOC_BEFORE_TAILCALL_V4:
    case Hexagon::RESTORE_DEALLOC_BEFORE_TAILCALL_V4_EXT:
    case Hexagon::RESTORE_DEALLOC_BEFORE_TAILCALL_V4_EXT_PIC:
    case Hexagon::RESTORE_DEALLOC_BEFORE_TAILCALL_V4_PIC:
    case Hexagon::RESTORE_DEALLOC_RET_JMP_V4:
    case Hexagon::RESTORE_DEALLOC_RET_JMP_V4_EXT:
    case Hexagon::RESTORE_DEALLOC_RET_JMP_V4_EXT_PIC:
    case Hexagon::RESTORE_DEALLOC_RET_JMP_V4_PIC:
    case Hexagon::SAVE_REGISTERS_CALL_V4:
    case Hexagon::SAVE_REGISTERS_CALL_V4STK:
    case Hexagon::SAVE_REGISTERS_CALL_V4STK_EXT:
    case Hexagon::SAVE_REGISTERS_CALL_V4STK_EXT_PIC:
    case Hexagon::SAVE_REGISTERS_CALL_V4STK_PIC:
    case Hexagon::SAVE_REGISTERS_CALL_V4_EXT:
    case Hexagon::SAVE_REGISTERS_CALL_V4_EXT_PIC:
    case Hexagon::SAVE_REGISTERS_CALL_V4_PIC: {
      switch (OpNum) {
      case 0:
        // op: dst
        return 1;
      }
      break;
    }
    case Hexagon::J2_loop0iext:
    case Hexagon::J2_loop1iext: {
      switch (OpNum) {
      case 0:
        // op: offset
        return 3;
      case 1:
        // op: src2
        return 0;
      }
      break;
    }
    case Hexagon::J2_loop0rext:
    case Hexagon::J2_loop1rext: {
      switch (OpNum) {
      case 0:
        // op: offset
        return 3;
      case 1:
        // op: src2
        return 16;
      }
      break;
    }
    case Hexagon::PS_jmpretf:
    case Hexagon::PS_jmpretfnew:
    case Hexagon::PS_jmpretfnewpt:
    case Hexagon::PS_jmprett:
    case Hexagon::PS_jmprettnew:
    case Hexagon::PS_jmprettnewpt: {
      switch (OpNum) {
      case 0:
        // op: src
        return 8;
      case 1:
        // op: dst
        return 16;
      }
      break;
    }
    case Hexagon::A2_tfrcrr: {
      switch (OpNum) {
      case 1:
        // op: Cs32
        return 16;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::A4_tfrcpp: {
      switch (OpNum) {
      case 1:
        // op: Css32
        return 16;
      case 0:
        // op: Rdd32
        return 0;
      }
      break;
    }
    case Hexagon::G4_tfrgcrr: {
      switch (OpNum) {
      case 1:
        // op: Gs32
        return 16;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::G4_tfrgcpp: {
      switch (OpNum) {
      case 1:
        // op: Gss32
        return 16;
      case 0:
        // op: Rdd32
        return 0;
      }
      break;
    }
    case Hexagon::S4_storerbnew_ap:
    case Hexagon::S4_storerhnew_ap:
    case Hexagon::S4_storerinew_ap: {
      switch (OpNum) {
      case 1:
        // op: II
        return 0;
      case 2:
        // op: Nt8
        return 8;
      case 0:
        // op: Re32
        return 16;
      }
      break;
    }
    case Hexagon::S4_storerb_ap:
    case Hexagon::S4_storerf_ap:
    case Hexagon::S4_storerh_ap:
    case Hexagon::S4_storeri_ap: {
      switch (OpNum) {
      case 1:
        // op: II
        return 0;
      case 2:
        // op: Rt32
        return 8;
      case 0:
        // op: Re32
        return 16;
      }
      break;
    }
    case Hexagon::S4_storerd_ap: {
      switch (OpNum) {
      case 1:
        // op: II
        return 0;
      case 2:
        // op: Rtt32
        return 8;
      case 0:
        // op: Re32
        return 16;
      }
      break;
    }
    case Hexagon::J4_cmpeqi_f_jumpnv_nt:
    case Hexagon::J4_cmpeqi_f_jumpnv_t:
    case Hexagon::J4_cmpeqi_t_jumpnv_nt:
    case Hexagon::J4_cmpeqi_t_jumpnv_t:
    case Hexagon::J4_cmpgti_f_jumpnv_nt:
    case Hexagon::J4_cmpgti_f_jumpnv_t:
    case Hexagon::J4_cmpgti_t_jumpnv_nt:
    case Hexagon::J4_cmpgti_t_jumpnv_t:
    case Hexagon::J4_cmpgtui_f_jumpnv_nt:
    case Hexagon::J4_cmpgtui_f_jumpnv_t:
    case Hexagon::J4_cmpgtui_t_jumpnv_nt:
    case Hexagon::J4_cmpgtui_t_jumpnv_t: {
      switch (OpNum) {
      case 1:
        // op: II
        return 8;
      case 2:
        // op: Ii
        return 1;
      case 0:
        // op: Ns8
        return 16;
      }
      break;
    }
    case Hexagon::J4_jumpseti: {
      switch (OpNum) {
      case 1:
        // op: II
        return 8;
      case 2:
        // op: Ii
        return 1;
      case 0:
        // op: Rd16
        return 16;
      }
      break;
    }
    case Hexagon::J4_cmpeqi_fp0_jump_nt:
    case Hexagon::J4_cmpeqi_fp0_jump_t:
    case Hexagon::J4_cmpeqi_fp1_jump_nt:
    case Hexagon::J4_cmpeqi_fp1_jump_t:
    case Hexagon::J4_cmpeqi_tp0_jump_nt:
    case Hexagon::J4_cmpeqi_tp0_jump_t:
    case Hexagon::J4_cmpeqi_tp1_jump_nt:
    case Hexagon::J4_cmpeqi_tp1_jump_t:
    case Hexagon::J4_cmpgti_fp0_jump_nt:
    case Hexagon::J4_cmpgti_fp0_jump_t:
    case Hexagon::J4_cmpgti_fp1_jump_nt:
    case Hexagon::J4_cmpgti_fp1_jump_t:
    case Hexagon::J4_cmpgti_tp0_jump_nt:
    case Hexagon::J4_cmpgti_tp0_jump_t:
    case Hexagon::J4_cmpgti_tp1_jump_nt:
    case Hexagon::J4_cmpgti_tp1_jump_t:
    case Hexagon::J4_cmpgtui_fp0_jump_nt:
    case Hexagon::J4_cmpgtui_fp0_jump_t:
    case Hexagon::J4_cmpgtui_fp1_jump_nt:
    case Hexagon::J4_cmpgtui_fp1_jump_t:
    case Hexagon::J4_cmpgtui_tp0_jump_nt:
    case Hexagon::J4_cmpgtui_tp0_jump_t:
    case Hexagon::J4_cmpgtui_tp1_jump_nt:
    case Hexagon::J4_cmpgtui_tp1_jump_t: {
      switch (OpNum) {
      case 1:
        // op: II
        return 8;
      case 2:
        // op: Ii
        return 1;
      case 0:
        // op: Rs16
        return 16;
      }
      break;
    }
    case Hexagon::SA1_cmpeqi:
    case Hexagon::SS2_storebi0:
    case Hexagon::SS2_storebi1:
    case Hexagon::SS2_storewi0:
    case Hexagon::SS2_storewi1: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 0;
      case 0:
        // op: Rs16
        return 4;
      }
      break;
    }
    case Hexagon::S2_storerbnew_io:
    case Hexagon::S2_storerhnew_io:
    case Hexagon::S2_storerinew_io: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 0;
      case 0:
        // op: Rs32
        return 16;
      case 2:
        // op: Nt8
        return 8;
      }
      break;
    }
    case Hexagon::S2_storerb_io:
    case Hexagon::S2_storerf_io:
    case Hexagon::S2_storerh_io:
    case Hexagon::S2_storeri_io: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 0;
      case 0:
        // op: Rs32
        return 16;
      case 2:
        // op: Rt32
        return 8;
      }
      break;
    }
    case Hexagon::S2_storerd_io: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 0;
      case 0:
        // op: Rs32
        return 16;
      case 2:
        // op: Rtt32
        return 8;
      }
      break;
    }
    case Hexagon::Y2_dcfetchbo: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 0;
      case 0:
        // op: Rs32
        return 16;
      }
      break;
    }
    case Hexagon::J4_tstbit0_f_jumpnv_nt:
    case Hexagon::J4_tstbit0_f_jumpnv_t:
    case Hexagon::J4_tstbit0_t_jumpnv_nt:
    case Hexagon::J4_tstbit0_t_jumpnv_t: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 1;
      case 0:
        // op: Ns8
        return 16;
      }
      break;
    }
    case Hexagon::J2_callf:
    case Hexagon::J2_callt:
    case Hexagon::J2_jumpf:
    case Hexagon::J2_jumpfnew:
    case Hexagon::J2_jumpfnewpt:
    case Hexagon::J2_jumpfpt:
    case Hexagon::J2_jumpt:
    case Hexagon::J2_jumptnew:
    case Hexagon::J2_jumptnewpt:
    case Hexagon::J2_jumptpt: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 1;
      case 0:
        // op: Pu4
        return 8;
      }
      break;
    }
    case Hexagon::J4_tstbit0_fp0_jump_nt:
    case Hexagon::J4_tstbit0_fp0_jump_t:
    case Hexagon::J4_tstbit0_fp1_jump_nt:
    case Hexagon::J4_tstbit0_fp1_jump_t:
    case Hexagon::J4_tstbit0_tp0_jump_nt:
    case Hexagon::J4_tstbit0_tp0_jump_t:
    case Hexagon::J4_tstbit0_tp1_jump_nt:
    case Hexagon::J4_tstbit0_tp1_jump_t: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 1;
      case 0:
        // op: Rs16
        return 16;
      }
      break;
    }
    case Hexagon::J2_jumprgtez:
    case Hexagon::J2_jumprgtezpt:
    case Hexagon::J2_jumprltez:
    case Hexagon::J2_jumprltezpt:
    case Hexagon::J2_jumprnz:
    case Hexagon::J2_jumprnzpt:
    case Hexagon::J2_jumprz:
    case Hexagon::J2_jumprzpt: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 1;
      case 0:
        // op: Rs32
        return 16;
      }
      break;
    }
    case Hexagon::S4_pstorerbnewf_abs:
    case Hexagon::S4_pstorerbnewfnew_abs:
    case Hexagon::S4_pstorerbnewt_abs:
    case Hexagon::S4_pstorerbnewtnew_abs:
    case Hexagon::S4_pstorerhnewf_abs:
    case Hexagon::S4_pstorerhnewfnew_abs:
    case Hexagon::S4_pstorerhnewt_abs:
    case Hexagon::S4_pstorerhnewtnew_abs:
    case Hexagon::S4_pstorerinewf_abs:
    case Hexagon::S4_pstorerinewfnew_abs:
    case Hexagon::S4_pstorerinewt_abs:
    case Hexagon::S4_pstorerinewtnew_abs: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 3;
      case 0:
        // op: Pv4
        return 0;
      case 2:
        // op: Nt8
        return 8;
      }
      break;
    }
    case Hexagon::S4_pstorerbf_abs:
    case Hexagon::S4_pstorerbfnew_abs:
    case Hexagon::S4_pstorerbt_abs:
    case Hexagon::S4_pstorerbtnew_abs:
    case Hexagon::S4_pstorerff_abs:
    case Hexagon::S4_pstorerffnew_abs:
    case Hexagon::S4_pstorerft_abs:
    case Hexagon::S4_pstorerftnew_abs:
    case Hexagon::S4_pstorerhf_abs:
    case Hexagon::S4_pstorerhfnew_abs:
    case Hexagon::S4_pstorerht_abs:
    case Hexagon::S4_pstorerhtnew_abs:
    case Hexagon::S4_pstorerif_abs:
    case Hexagon::S4_pstorerifnew_abs:
    case Hexagon::S4_pstorerit_abs:
    case Hexagon::S4_pstoreritnew_abs: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 3;
      case 0:
        // op: Pv4
        return 0;
      case 2:
        // op: Rt32
        return 8;
      }
      break;
    }
    case Hexagon::S4_pstorerdf_abs:
    case Hexagon::S4_pstorerdfnew_abs:
    case Hexagon::S4_pstorerdt_abs:
    case Hexagon::S4_pstorerdtnew_abs: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 3;
      case 0:
        // op: Pv4
        return 0;
      case 2:
        // op: Rtt32
        return 8;
      }
      break;
    }
    case Hexagon::SL2_loadrd_sp: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 3;
      case 0:
        // op: Rdd8
        return 0;
      }
      break;
    }
    case Hexagon::S4_addi_asl_ri:
    case Hexagon::S4_addi_lsr_ri:
    case Hexagon::S4_andi_asl_ri:
    case Hexagon::S4_andi_lsr_ri:
    case Hexagon::S4_ori_asl_ri:
    case Hexagon::S4_ori_lsr_ri:
    case Hexagon::S4_subi_asl_ri:
    case Hexagon::S4_subi_lsr_ri: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 3;
      case 3:
        // op: II
        return 8;
      case 0:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::SA1_addsp:
    case Hexagon::SA1_seti:
    case Hexagon::SL2_loadri_sp: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 4;
      case 0:
        // op: Rd16
        return 0;
      }
      break;
    }
    case Hexagon::A2_tfrsi:
    case Hexagon::F2_sfimm_n:
    case Hexagon::F2_sfimm_p:
    case Hexagon::L2_loadrbgp:
    case Hexagon::L2_loadrhgp:
    case Hexagon::L2_loadrigp:
    case Hexagon::L2_loadrubgp:
    case Hexagon::L2_loadruhgp:
    case Hexagon::PS_loadrbabs:
    case Hexagon::PS_loadrhabs:
    case Hexagon::PS_loadriabs:
    case Hexagon::PS_loadrubabs:
    case Hexagon::PS_loadruhabs: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 5;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::F2_dfimm_n:
    case Hexagon::F2_dfimm_p:
    case Hexagon::L2_loadrdgp:
    case Hexagon::PS_loadrdabs: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 5;
      case 0:
        // op: Rdd32
        return 0;
      }
      break;
    }
    case Hexagon::SA1_combine0i:
    case Hexagon::SA1_combine1i:
    case Hexagon::SA1_combine2i:
    case Hexagon::SA1_combine3i: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 5;
      case 0:
        // op: Rdd8
        return 0;
      }
      break;
    }
    case Hexagon::A2_combineii:
    case Hexagon::A4_combineii: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 5;
      case 2:
        // op: II
        return 13;
      case 0:
        // op: Rdd32
        return 0;
      }
      break;
    }
    case Hexagon::A2_subri: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 5;
      case 2:
        // op: Rs32
        return 16;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::A4_combineir: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 5;
      case 2:
        // op: Rs32
        return 16;
      case 0:
        // op: Rdd32
        return 0;
      }
      break;
    }
    case Hexagon::M4_mpyrr_addi: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 5;
      case 2:
        // op: Rs32
        return 16;
      case 3:
        // op: Rt32
        return 8;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::S4_lsli: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 5;
      case 2:
        // op: Rt32
        return 8;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::M4_mpyri_addi: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 5;
      case 3:
        // op: II
        return 0;
      case 2:
        // op: Rs32
        return 16;
      case 0:
        // op: Rd32
        return 8;
      }
      break;
    }
    case Hexagon::S4_storerbnew_ur:
    case Hexagon::S4_storerhnew_ur:
    case Hexagon::S4_storerinew_ur: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 6;
      case 2:
        // op: II
        return 0;
      case 0:
        // op: Ru32
        return 16;
      case 3:
        // op: Nt8
        return 8;
      }
      break;
    }
    case Hexagon::S4_storerb_ur:
    case Hexagon::S4_storerf_ur:
    case Hexagon::S4_storerh_ur:
    case Hexagon::S4_storeri_ur: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 6;
      case 2:
        // op: II
        return 0;
      case 0:
        // op: Ru32
        return 16;
      case 3:
        // op: Rt32
        return 8;
      }
      break;
    }
    case Hexagon::S4_storerd_ur: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 6;
      case 2:
        // op: II
        return 0;
      case 0:
        // op: Ru32
        return 16;
      case 3:
        // op: Rtt32
        return 8;
      }
      break;
    }
    case Hexagon::C4_addipc: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 7;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::L4_add_memopb_io:
    case Hexagon::L4_add_memoph_io:
    case Hexagon::L4_add_memopw_io:
    case Hexagon::L4_and_memopb_io:
    case Hexagon::L4_and_memoph_io:
    case Hexagon::L4_and_memopw_io:
    case Hexagon::L4_or_memopb_io:
    case Hexagon::L4_or_memoph_io:
    case Hexagon::L4_or_memopw_io:
    case Hexagon::L4_sub_memopb_io:
    case Hexagon::L4_sub_memoph_io:
    case Hexagon::L4_sub_memopw_io: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 7;
      case 0:
        // op: Rs32
        return 16;
      case 2:
        // op: Rt32
        return 0;
      }
      break;
    }
    case Hexagon::L4_iadd_memopb_io:
    case Hexagon::L4_iadd_memoph_io:
    case Hexagon::L4_iadd_memopw_io:
    case Hexagon::L4_iand_memopb_io:
    case Hexagon::L4_iand_memoph_io:
    case Hexagon::L4_iand_memopw_io:
    case Hexagon::L4_ior_memopb_io:
    case Hexagon::L4_ior_memoph_io:
    case Hexagon::L4_ior_memopw_io:
    case Hexagon::L4_isub_memopb_io:
    case Hexagon::L4_isub_memoph_io:
    case Hexagon::L4_isub_memopw_io:
    case Hexagon::S4_storeirb_io:
    case Hexagon::S4_storeirh_io:
    case Hexagon::S4_storeiri_io: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 7;
      case 2:
        // op: II
        return 0;
      case 0:
        // op: Rs32
        return 16;
      }
      break;
    }
    case Hexagon::V6_vwhist128qm: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 8;
      case 0:
        // op: Qv4
        return 22;
      }
      break;
    }
    case Hexagon::SS1_storeb_io:
    case Hexagon::SS1_storew_io:
    case Hexagon::SS2_storeh_io: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 8;
      case 0:
        // op: Rs16
        return 4;
      case 2:
        // op: Rt16
        return 0;
      }
      break;
    }
    case Hexagon::V6_vS32b_new_ai:
    case Hexagon::V6_vS32b_nt_new_ai: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 8;
      case 0:
        // op: Rt32
        return 16;
      case 2:
        // op: Os8
        return 0;
      }
      break;
    }
    case Hexagon::V6_vS32Ub_ai:
    case Hexagon::V6_vS32b_ai:
    case Hexagon::V6_vS32b_nt_ai: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 8;
      case 0:
        // op: Rt32
        return 16;
      case 2:
        // op: Vs32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vS32b_srls_ai:
    case Hexagon::V6_zLd_ai: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 8;
      case 0:
        // op: Rt32
        return 16;
      }
      break;
    }
    case Hexagon::S2_mask: {
      switch (OpNum) {
      case 1:
        // op: Ii
        return 8;
      case 2:
        // op: II
        return 5;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::C2_all8:
    case Hexagon::C2_any8:
    case Hexagon::C2_not: {
      switch (OpNum) {
      case 1:
        // op: Ps4
        return 16;
      case 0:
        // op: Pd4
        return 0;
      }
      break;
    }
    case Hexagon::C2_tfrpr: {
      switch (OpNum) {
      case 1:
        // op: Ps4
        return 16;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::C2_xor:
    case Hexagon::C4_fastcorner9:
    case Hexagon::C4_fastcorner9_not: {
      switch (OpNum) {
      case 1:
        // op: Ps4
        return 16;
      case 2:
        // op: Pt4
        return 8;
      case 0:
        // op: Pd4
        return 0;
      }
      break;
    }
    case Hexagon::C2_vitpack: {
      switch (OpNum) {
      case 1:
        // op: Ps4
        return 16;
      case 2:
        // op: Pt4
        return 8;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::C4_and_and:
    case Hexagon::C4_and_andn:
    case Hexagon::C4_and_or:
    case Hexagon::C4_and_orn:
    case Hexagon::C4_or_and:
    case Hexagon::C4_or_andn:
    case Hexagon::C4_or_or:
    case Hexagon::C4_or_orn: {
      switch (OpNum) {
      case 1:
        // op: Ps4
        return 16;
      case 2:
        // op: Pt4
        return 8;
      case 3:
        // op: Pu4
        return 6;
      case 0:
        // op: Pd4
        return 0;
      }
      break;
    }
    case Hexagon::V6_vcmov:
    case Hexagon::V6_vncmov: {
      switch (OpNum) {
      case 1:
        // op: Ps4
        return 5;
      case 2:
        // op: Vu32
        return 8;
      case 0:
        // op: Vd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vccombine:
    case Hexagon::V6_vnccombine: {
      switch (OpNum) {
      case 1:
        // op: Ps4
        return 5;
      case 2:
        // op: Vu32
        return 8;
      case 3:
        // op: Vv32
        return 16;
      case 0:
        // op: Vdd32
        return 0;
      }
      break;
    }
    case Hexagon::C2_mask: {
      switch (OpNum) {
      case 1:
        // op: Pt4
        return 8;
      case 0:
        // op: Rdd32
        return 0;
      }
      break;
    }
    case Hexagon::C2_and:
    case Hexagon::C2_andn:
    case Hexagon::C2_or:
    case Hexagon::C2_orn: {
      switch (OpNum) {
      case 1:
        // op: Pt4
        return 8;
      case 2:
        // op: Ps4
        return 16;
      case 0:
        // op: Pd4
        return 0;
      }
      break;
    }
    case Hexagon::A2_paddf:
    case Hexagon::A2_paddfnew:
    case Hexagon::A2_paddt:
    case Hexagon::A2_paddtnew:
    case Hexagon::A2_pandf:
    case Hexagon::A2_pandfnew:
    case Hexagon::A2_pandt:
    case Hexagon::A2_pandtnew:
    case Hexagon::A2_porf:
    case Hexagon::A2_porfnew:
    case Hexagon::A2_port:
    case Hexagon::A2_portnew:
    case Hexagon::A2_pxorf:
    case Hexagon::A2_pxorfnew:
    case Hexagon::A2_pxort:
    case Hexagon::A2_pxortnew:
    case Hexagon::C2_mux: {
      switch (OpNum) {
      case 1:
        // op: Pu4
        return 5;
      case 2:
        // op: Rs32
        return 16;
      case 3:
        // op: Rt32
        return 8;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::C2_ccombinewf:
    case Hexagon::C2_ccombinewnewf:
    case Hexagon::C2_ccombinewnewt:
    case Hexagon::C2_ccombinewt: {
      switch (OpNum) {
      case 1:
        // op: Pu4
        return 5;
      case 2:
        // op: Rs32
        return 16;
      case 3:
        // op: Rt32
        return 8;
      case 0:
        // op: Rdd32
        return 0;
      }
      break;
    }
    case Hexagon::C2_vmux: {
      switch (OpNum) {
      case 1:
        // op: Pu4
        return 5;
      case 2:
        // op: Rss32
        return 16;
      case 3:
        // op: Rtt32
        return 8;
      case 0:
        // op: Rdd32
        return 0;
      }
      break;
    }
    case Hexagon::A2_psubf:
    case Hexagon::A2_psubfnew:
    case Hexagon::A2_psubt:
    case Hexagon::A2_psubtnew: {
      switch (OpNum) {
      case 1:
        // op: Pu4
        return 5;
      case 2:
        // op: Rt32
        return 8;
      case 3:
        // op: Rs32
        return 16;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::A4_paslhf:
    case Hexagon::A4_paslhfnew:
    case Hexagon::A4_paslht:
    case Hexagon::A4_paslhtnew:
    case Hexagon::A4_pasrhf:
    case Hexagon::A4_pasrhfnew:
    case Hexagon::A4_pasrht:
    case Hexagon::A4_pasrhtnew:
    case Hexagon::A4_psxtbf:
    case Hexagon::A4_psxtbfnew:
    case Hexagon::A4_psxtbt:
    case Hexagon::A4_psxtbtnew:
    case Hexagon::A4_psxthf:
    case Hexagon::A4_psxthfnew:
    case Hexagon::A4_psxtht:
    case Hexagon::A4_psxthtnew:
    case Hexagon::A4_pzxtbf:
    case Hexagon::A4_pzxtbfnew:
    case Hexagon::A4_pzxtbt:
    case Hexagon::A4_pzxtbtnew:
    case Hexagon::A4_pzxthf:
    case Hexagon::A4_pzxthfnew:
    case Hexagon::A4_pzxtht:
    case Hexagon::A4_pzxthtnew: {
      switch (OpNum) {
      case 1:
        // op: Pu4
        return 8;
      case 2:
        // op: Rs32
        return 16;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_zLd_pred_ppu: {
      switch (OpNum) {
      case 1:
        // op: Pv4
        return 11;
      case 3:
        // op: Mu2
        return 13;
      case 0:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::V6_vS32b_new_npred_ppu:
    case Hexagon::V6_vS32b_new_pred_ppu:
    case Hexagon::V6_vS32b_nt_new_npred_ppu:
    case Hexagon::V6_vS32b_nt_new_pred_ppu: {
      switch (OpNum) {
      case 1:
        // op: Pv4
        return 11;
      case 3:
        // op: Mu2
        return 13;
      case 4:
        // op: Os8
        return 0;
      case 0:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::V6_vS32Ub_npred_ppu:
    case Hexagon::V6_vS32Ub_pred_ppu:
    case Hexagon::V6_vS32b_npred_ppu:
    case Hexagon::V6_vS32b_nt_npred_ppu:
    case Hexagon::V6_vS32b_nt_pred_ppu:
    case Hexagon::V6_vS32b_pred_ppu: {
      switch (OpNum) {
      case 1:
        // op: Pv4
        return 11;
      case 3:
        // op: Mu2
        return 13;
      case 4:
        // op: Vs32
        return 0;
      case 0:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::L4_return_f:
    case Hexagon::L4_return_fnew_pnt:
    case Hexagon::L4_return_fnew_pt:
    case Hexagon::L4_return_t:
    case Hexagon::L4_return_tnew_pnt:
    case Hexagon::L4_return_tnew_pt: {
      switch (OpNum) {
      case 1:
        // op: Pv4
        return 8;
      case 2:
        // op: Rs32
        return 16;
      case 0:
        // op: Rdd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_pred_not: {
      switch (OpNum) {
      case 1:
        // op: Qs4
        return 8;
      case 0:
        // op: Qd4
        return 0;
      }
      break;
    }
    case Hexagon::V6_pred_and:
    case Hexagon::V6_pred_and_n:
    case Hexagon::V6_pred_or:
    case Hexagon::V6_pred_or_n:
    case Hexagon::V6_pred_xor:
    case Hexagon::V6_shuffeqh:
    case Hexagon::V6_shuffeqw: {
      switch (OpNum) {
      case 1:
        // op: Qs4
        return 8;
      case 2:
        // op: Qt4
        return 22;
      case 0:
        // op: Qd4
        return 0;
      }
      break;
    }
    case Hexagon::V6_vmux: {
      switch (OpNum) {
      case 1:
        // op: Qt4
        return 5;
      case 2:
        // op: Vu32
        return 8;
      case 3:
        // op: Vv32
        return 16;
      case 0:
        // op: Vd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vswap: {
      switch (OpNum) {
      case 1:
        // op: Qt4
        return 5;
      case 2:
        // op: Vu32
        return 8;
      case 3:
        // op: Vv32
        return 16;
      case 0:
        // op: Vdd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vandnqrt:
    case Hexagon::V6_vandqrt: {
      switch (OpNum) {
      case 1:
        // op: Qu4
        return 8;
      case 2:
        // op: Rt32
        return 16;
      case 0:
        // op: Vd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vS32b_nqpred_ppu:
    case Hexagon::V6_vS32b_nt_nqpred_ppu:
    case Hexagon::V6_vS32b_nt_qpred_ppu:
    case Hexagon::V6_vS32b_qpred_ppu: {
      switch (OpNum) {
      case 1:
        // op: Qv4
        return 11;
      case 3:
        // op: Mu2
        return 13;
      case 4:
        // op: Vs32
        return 0;
      case 0:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::V6_vprefixqb:
    case Hexagon::V6_vprefixqh:
    case Hexagon::V6_vprefixqw: {
      switch (OpNum) {
      case 1:
        // op: Qv4
        return 22;
      case 0:
        // op: Vd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vandvnqv:
    case Hexagon::V6_vandvqv: {
      switch (OpNum) {
      case 1:
        // op: Qv4
        return 22;
      case 2:
        // op: Vu32
        return 8;
      case 0:
        // op: Vd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vaddbnq:
    case Hexagon::V6_vaddbq:
    case Hexagon::V6_vaddhnq:
    case Hexagon::V6_vaddhq:
    case Hexagon::V6_vaddwnq:
    case Hexagon::V6_vaddwq:
    case Hexagon::V6_vsubbnq:
    case Hexagon::V6_vsubbq:
    case Hexagon::V6_vsubhnq:
    case Hexagon::V6_vsubhq:
    case Hexagon::V6_vsubwnq:
    case Hexagon::V6_vsubwq: {
      switch (OpNum) {
      case 1:
        // op: Qv4
        return 22;
      case 3:
        // op: Vu32
        return 8;
      case 0:
        // op: Vx32
        return 0;
      }
      break;
    }
    case Hexagon::SA1_and1:
    case Hexagon::SA1_dec:
    case Hexagon::SA1_inc:
    case Hexagon::SA1_sxtb:
    case Hexagon::SA1_sxth:
    case Hexagon::SA1_tfr:
    case Hexagon::SA1_zxtb:
    case Hexagon::SA1_zxth: {
      switch (OpNum) {
      case 1:
        // op: Rs16
        return 4;
      case 0:
        // op: Rd16
        return 0;
      }
      break;
    }
    case Hexagon::SA1_combinerz:
    case Hexagon::SA1_combinezr: {
      switch (OpNum) {
      case 1:
        // op: Rs16
        return 4;
      case 0:
        // op: Rdd8
        return 0;
      }
      break;
    }
    case Hexagon::A2_tfrrcr: {
      switch (OpNum) {
      case 1:
        // op: Rs32
        return 16;
      case 0:
        // op: Cd32
        return 0;
      }
      break;
    }
    case Hexagon::G4_tfrgrcr: {
      switch (OpNum) {
      case 1:
        // op: Rs32
        return 16;
      case 0:
        // op: Gd32
        return 0;
      }
      break;
    }
    case Hexagon::C2_tfrrp:
    case Hexagon::Y5_l2locka: {
      switch (OpNum) {
      case 1:
        // op: Rs32
        return 16;
      case 0:
        // op: Pd4
        return 0;
      }
      break;
    }
    case Hexagon::A2_abs:
    case Hexagon::A2_abssat:
    case Hexagon::A2_aslh:
    case Hexagon::A2_asrh:
    case Hexagon::A2_negsat:
    case Hexagon::A2_satb:
    case Hexagon::A2_sath:
    case Hexagon::A2_satub:
    case Hexagon::A2_satuh:
    case Hexagon::A2_swiz:
    case Hexagon::A2_sxtb:
    case Hexagon::A2_sxth:
    case Hexagon::A2_tfr:
    case Hexagon::A2_zxth:
    case Hexagon::F2_conv_sf2uw:
    case Hexagon::F2_conv_sf2uw_chop:
    case Hexagon::F2_conv_sf2w:
    case Hexagon::F2_conv_sf2w_chop:
    case Hexagon::F2_conv_uw2sf:
    case Hexagon::F2_conv_w2sf:
    case Hexagon::F2_sffixupr:
    case Hexagon::L2_loadw_aq:
    case Hexagon::L2_loadw_locked:
    case Hexagon::S2_brev:
    case Hexagon::S2_cl0:
    case Hexagon::S2_cl1:
    case Hexagon::S2_clb:
    case Hexagon::S2_clbnorm:
    case Hexagon::S2_ct0:
    case Hexagon::S2_ct1:
    case Hexagon::S2_svsathb:
    case Hexagon::S2_svsathub:
    case Hexagon::S2_vsplatrb:
    case Hexagon::Y2_dctagr:
    case Hexagon::Y2_getimask:
    case Hexagon::Y2_iassignr:
    case Hexagon::Y2_icdatar:
    case Hexagon::Y2_ictagr:
    case Hexagon::Y2_tlbp:
    case Hexagon::Y4_l2tagr: {
      switch (OpNum) {
      case 1:
        // op: Rs32
        return 16;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::A2_sxtw:
    case Hexagon::F2_conv_sf2d:
    case Hexagon::F2_conv_sf2d_chop:
    case Hexagon::F2_conv_sf2df:
    case Hexagon::F2_conv_sf2ud:
    case Hexagon::F2_conv_sf2ud_chop:
    case Hexagon::F2_conv_uw2df:
    case Hexagon::F2_conv_w2df:
    case Hexagon::L2_deallocframe:
    case Hexagon::L4_loadd_aq:
    case Hexagon::L4_loadd_locked:
    case Hexagon::L4_return:
    case Hexagon::S2_vsplatrh:
    case Hexagon::S2_vsxtbh:
    case Hexagon::S2_vsxthw:
    case Hexagon::S2_vzxtbh:
    case Hexagon::S2_vzxthw:
    case Hexagon::S6_vsplatrbp:
    case Hexagon::Y2_tlbr: {
      switch (OpNum) {
      case 1:
        // op: Rs32
        return 16;
      case 0:
        // op: Rdd32
        return 0;
      }
      break;
    }
    case Hexagon::Y2_tfrsrcr: {
      switch (OpNum) {
      case 1:
        // op: Rs32
        return 16;
      case 0:
        // op: Sd128
        return 0;
      }
      break;
    }
    case Hexagon::A4_cmpbeq:
    case Hexagon::A4_cmpbgt:
    case Hexagon::A4_cmpbgtu:
    case Hexagon::A4_cmpheq:
    case Hexagon::A4_cmphgt:
    case Hexagon::A4_cmphgtu:
    case Hexagon::C2_bitsclr:
    case Hexagon::C2_bitsset:
    case Hexagon::C2_cmpeq:
    case Hexagon::C2_cmpgt:
    case Hexagon::C2_cmpgtu:
    case Hexagon::C4_cmplte:
    case Hexagon::C4_cmplteu:
    case Hexagon::C4_cmpneq:
    case Hexagon::C4_nbitsclr:
    case Hexagon::C4_nbitsset:
    case Hexagon::F2_sfcmpeq:
    case Hexagon::F2_sfcmpge:
    case Hexagon::F2_sfcmpgt:
    case Hexagon::F2_sfcmpuo:
    case Hexagon::S2_storew_locked:
    case Hexagon::S2_tstbit_r:
    case Hexagon::S4_ntstbit_r: {
      switch (OpNum) {
      case 1:
        // op: Rs32
        return 16;
      case 2:
        // op: Rt32
        return 8;
      case 0:
        // op: Pd4
        return 0;
      }
      break;
    }
    case Hexagon::A2_add:
    case Hexagon::A2_addsat:
    case Hexagon::A2_and:
    case Hexagon::A2_max:
    case Hexagon::A2_maxu:
    case Hexagon::A2_or:
    case Hexagon::A2_svaddh:
    case Hexagon::A2_svaddhs:
    case Hexagon::A2_svadduhs:
    case Hexagon::A2_svavgh:
    case Hexagon::A2_svavghs:
    case Hexagon::A2_xor:
    case Hexagon::A4_cround_rr:
    case Hexagon::A4_modwrapu:
    case Hexagon::A4_rcmpeq:
    case Hexagon::A4_rcmpneq:
    case Hexagon::A4_round_rr:
    case Hexagon::A4_round_rr_sat:
    case Hexagon::F2_sfadd:
    case Hexagon::F2_sffixupd:
    case Hexagon::F2_sffixupn:
    case Hexagon::F2_sfmax:
    case Hexagon::F2_sfmin:
    case Hexagon::F2_sfmpy:
    case Hexagon::F2_sfsub:
    case Hexagon::L4_loadw_phys:
    case Hexagon::M2_cmpyrs_s0:
    case Hexagon::M2_cmpyrs_s1:
    case Hexagon::M2_cmpyrsc_s0:
    case Hexagon::M2_cmpyrsc_s1:
    case Hexagon::M2_dpmpyss_rnd_s0:
    case Hexagon::M2_hmmpyh_rs1:
    case Hexagon::M2_hmmpyh_s1:
    case Hexagon::M2_hmmpyl_rs1:
    case Hexagon::M2_hmmpyl_s1:
    case Hexagon::M2_mpy_hh_s0:
    case Hexagon::M2_mpy_hh_s1:
    case Hexagon::M2_mpy_hl_s0:
    case Hexagon::M2_mpy_hl_s1:
    case Hexagon::M2_mpy_lh_s0:
    case Hexagon::M2_mpy_lh_s1:
    case Hexagon::M2_mpy_ll_s0:
    case Hexagon::M2_mpy_ll_s1:
    case Hexagon::M2_mpy_rnd_hh_s0:
    case Hexagon::M2_mpy_rnd_hh_s1:
    case Hexagon::M2_mpy_rnd_hl_s0:
    case Hexagon::M2_mpy_rnd_hl_s1:
    case Hexagon::M2_mpy_rnd_lh_s0:
    case Hexagon::M2_mpy_rnd_lh_s1:
    case Hexagon::M2_mpy_rnd_ll_s0:
    case Hexagon::M2_mpy_rnd_ll_s1:
    case Hexagon::M2_mpy_sat_hh_s0:
    case Hexagon::M2_mpy_sat_hh_s1:
    case Hexagon::M2_mpy_sat_hl_s0:
    case Hexagon::M2_mpy_sat_hl_s1:
    case Hexagon::M2_mpy_sat_lh_s0:
    case Hexagon::M2_mpy_sat_lh_s1:
    case Hexagon::M2_mpy_sat_ll_s0:
    case Hexagon::M2_mpy_sat_ll_s1:
    case Hexagon::M2_mpy_sat_rnd_hh_s0:
    case Hexagon::M2_mpy_sat_rnd_hh_s1:
    case Hexagon::M2_mpy_sat_rnd_hl_s0:
    case Hexagon::M2_mpy_sat_rnd_hl_s1:
    case Hexagon::M2_mpy_sat_rnd_lh_s0:
    case Hexagon::M2_mpy_sat_rnd_lh_s1:
    case Hexagon::M2_mpy_sat_rnd_ll_s0:
    case Hexagon::M2_mpy_sat_rnd_ll_s1:
    case Hexagon::M2_mpy_up:
    case Hexagon::M2_mpy_up_s1:
    case Hexagon::M2_mpy_up_s1_sat:
    case Hexagon::M2_mpyi:
    case Hexagon::M2_mpysu_up:
    case Hexagon::M2_mpyu_hh_s0:
    case Hexagon::M2_mpyu_hh_s1:
    case Hexagon::M2_mpyu_hl_s0:
    case Hexagon::M2_mpyu_hl_s1:
    case Hexagon::M2_mpyu_lh_s0:
    case Hexagon::M2_mpyu_lh_s1:
    case Hexagon::M2_mpyu_ll_s0:
    case Hexagon::M2_mpyu_ll_s1:
    case Hexagon::M2_mpyu_up:
    case Hexagon::M2_vmpy2s_s0pack:
    case Hexagon::M2_vmpy2s_s1pack:
    case Hexagon::S2_asl_r_r:
    case Hexagon::S2_asl_r_r_sat:
    case Hexagon::S2_asr_r_r:
    case Hexagon::S2_asr_r_r_sat:
    case Hexagon::S2_clrbit_r:
    case Hexagon::S2_lsl_r_r:
    case Hexagon::S2_lsr_r_r:
    case Hexagon::S2_setbit_r:
    case Hexagon::S2_togglebit_r:
    case Hexagon::S4_parity:
    case Hexagon::dep_A2_addsat: {
      switch (OpNum) {
      case 1:
        // op: Rs32
        return 16;
      case 2:
        // op: Rt32
        return 8;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::A2_combinew:
    case Hexagon::A4_bitsplit:
    case Hexagon::M2_cmpyi_s0:
    case Hexagon::M2_cmpyr_s0:
    case Hexagon::M2_cmpys_s0:
    case Hexagon::M2_cmpys_s1:
    case Hexagon::M2_cmpysc_s0:
    case Hexagon::M2_cmpysc_s1:
    case Hexagon::M2_dpmpyss_s0:
    case Hexagon::M2_dpmpyuu_s0:
    case Hexagon::M2_mpyd_hh_s0:
    case Hexagon::M2_mpyd_hh_s1:
    case Hexagon::M2_mpyd_hl_s0:
    case Hexagon::M2_mpyd_hl_s1:
    case Hexagon::M2_mpyd_lh_s0:
    case Hexagon::M2_mpyd_lh_s1:
    case Hexagon::M2_mpyd_ll_s0:
    case Hexagon::M2_mpyd_ll_s1:
    case Hexagon::M2_mpyd_rnd_hh_s0:
    case Hexagon::M2_mpyd_rnd_hh_s1:
    case Hexagon::M2_mpyd_rnd_hl_s0:
    case Hexagon::M2_mpyd_rnd_hl_s1:
    case Hexagon::M2_mpyd_rnd_lh_s0:
    case Hexagon::M2_mpyd_rnd_lh_s1:
    case Hexagon::M2_mpyd_rnd_ll_s0:
    case Hexagon::M2_mpyd_rnd_ll_s1:
    case Hexagon::M2_mpyud_hh_s0:
    case Hexagon::M2_mpyud_hh_s1:
    case Hexagon::M2_mpyud_hl_s0:
    case Hexagon::M2_mpyud_hl_s1:
    case Hexagon::M2_mpyud_lh_s0:
    case Hexagon::M2_mpyud_lh_s1:
    case Hexagon::M2_mpyud_ll_s0:
    case Hexagon::M2_mpyud_ll_s1:
    case Hexagon::M2_vmpy2s_s0:
    case Hexagon::M2_vmpy2s_s1:
    case Hexagon::M2_vmpy2su_s0:
    case Hexagon::M2_vmpy2su_s1:
    case Hexagon::M4_pmpyw:
    case Hexagon::M4_vpmpyh:
    case Hexagon::M5_vmpybsu:
    case Hexagon::M5_vmpybuu:
    case Hexagon::S2_packhl:
    case Hexagon::dep_S2_packhl: {
      switch (OpNum) {
      case 1:
        // op: Rs32
        return 16;
      case 2:
        // op: Rt32
        return 8;
      case 0:
        // op: Rdd32
        return 0;
      }
      break;
    }
    case Hexagon::S4_stored_locked: {
      switch (OpNum) {
      case 1:
        // op: Rs32
        return 16;
      case 2:
        // op: Rtt32
        return 8;
      case 0:
        // op: Pd4
        return 0;
      }
      break;
    }
    case Hexagon::S2_extractu_rp:
    case Hexagon::S4_extract_rp: {
      switch (OpNum) {
      case 1:
        // op: Rs32
        return 16;
      case 2:
        // op: Rtt32
        return 8;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::A4_tfrpcp: {
      switch (OpNum) {
      case 1:
        // op: Rss32
        return 16;
      case 0:
        // op: Cdd32
        return 0;
      }
      break;
    }
    case Hexagon::G4_tfrgpcp: {
      switch (OpNum) {
      case 1:
        // op: Rss32
        return 16;
      case 0:
        // op: Gdd32
        return 0;
      }
      break;
    }
    case Hexagon::A2_roundsat:
    case Hexagon::A2_sat:
    case Hexagon::F2_conv_d2sf:
    case Hexagon::F2_conv_df2sf:
    case Hexagon::F2_conv_df2uw:
    case Hexagon::F2_conv_df2uw_chop:
    case Hexagon::F2_conv_df2w:
    case Hexagon::F2_conv_df2w_chop:
    case Hexagon::F2_conv_ud2sf:
    case Hexagon::S2_cl0p:
    case Hexagon::S2_cl1p:
    case Hexagon::S2_clbp:
    case Hexagon::S2_ct0p:
    case Hexagon::S2_ct1p:
    case Hexagon::S2_vrndpackwh:
    case Hexagon::S2_vrndpackwhs:
    case Hexagon::S2_vsathb:
    case Hexagon::S2_vsathub:
    case Hexagon::S2_vsatwh:
    case Hexagon::S2_vsatwuh:
    case Hexagon::S2_vtrunehb:
    case Hexagon::S2_vtrunohb:
    case Hexagon::S4_clbpnorm:
    case Hexagon::S5_popcountp:
    case Hexagon::Y2_tlbpp:
    case Hexagon::Y5_tlboc: {
      switch (OpNum) {
      case 1:
        // op: Rss32
        return 16;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::A2_absp:
    case Hexagon::A2_negp:
    case Hexagon::A2_notp:
    case Hexagon::A2_vabsh:
    case Hexagon::A2_vabshsat:
    case Hexagon::A2_vabsw:
    case Hexagon::A2_vabswsat:
    case Hexagon::A2_vconj:
    case Hexagon::F2_conv_d2df:
    case Hexagon::F2_conv_df2d:
    case Hexagon::F2_conv_df2d_chop:
    case Hexagon::F2_conv_df2ud:
    case Hexagon::F2_conv_df2ud_chop:
    case Hexagon::F2_conv_ud2df:
    case Hexagon::S2_brevp:
    case Hexagon::S2_deinterleave:
    case Hexagon::S2_interleave:
    case Hexagon::S2_vsathb_nopack:
    case Hexagon::S2_vsathub_nopack:
    case Hexagon::S2_vsatwh_nopack:
    case Hexagon::S2_vsatwuh_nopack: {
      switch (OpNum) {
      case 1:
        // op: Rss32
        return 16;
      case 0:
        // op: Rdd32
        return 0;
      }
      break;
    }
    case Hexagon::Y4_tfrspcp: {
      switch (OpNum) {
      case 1:
        // op: Rss32
        return 16;
      case 0:
        // op: Sdd128
        return 0;
      }
      break;
    }
    case Hexagon::A4_tlbmatch: {
      switch (OpNum) {
      case 1:
        // op: Rss32
        return 16;
      case 2:
        // op: Rt32
        return 8;
      case 0:
        // op: Pd4
        return 0;
      }
      break;
    }
    case Hexagon::M4_cmpyi_wh:
    case Hexagon::M4_cmpyi_whc:
    case Hexagon::M4_cmpyr_wh:
    case Hexagon::M4_cmpyr_whc:
    case Hexagon::S2_asr_r_svw_trun:
    case Hexagon::Y5_ctlbw: {
      switch (OpNum) {
      case 1:
        // op: Rss32
        return 16;
      case 2:
        // op: Rt32
        return 8;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::A7_croundd_rr:
    case Hexagon::S2_asl_r_p:
    case Hexagon::S2_asl_r_vh:
    case Hexagon::S2_asl_r_vw:
    case Hexagon::S2_asr_r_p:
    case Hexagon::S2_asr_r_vh:
    case Hexagon::S2_asr_r_vw:
    case Hexagon::S2_lsl_r_p:
    case Hexagon::S2_lsl_r_vh:
    case Hexagon::S2_lsl_r_vw:
    case Hexagon::S2_lsr_r_p:
    case Hexagon::S2_lsr_r_vh:
    case Hexagon::S2_lsr_r_vw:
    case Hexagon::S2_vcnegh:
    case Hexagon::S2_vcrotate: {
      switch (OpNum) {
      case 1:
        // op: Rss32
        return 16;
      case 2:
        // op: Rt32
        return 8;
      case 0:
        // op: Rdd32
        return 0;
      }
      break;
    }
    case Hexagon::A2_vcmpbeq:
    case Hexagon::A2_vcmpbgtu:
    case Hexagon::A2_vcmpheq:
    case Hexagon::A2_vcmphgt:
    case Hexagon::A2_vcmphgtu:
    case Hexagon::A2_vcmpweq:
    case Hexagon::A2_vcmpwgt:
    case Hexagon::A2_vcmpwgtu:
    case Hexagon::A4_boundscheck_hi:
    case Hexagon::A4_boundscheck_lo:
    case Hexagon::A4_vcmpbeq_any:
    case Hexagon::A4_vcmpbgt:
    case Hexagon::A6_vcmpbeq_notany:
    case Hexagon::C2_cmpeqp:
    case Hexagon::C2_cmpgtp:
    case Hexagon::C2_cmpgtup:
    case Hexagon::F2_dfcmpeq:
    case Hexagon::F2_dfcmpge:
    case Hexagon::F2_dfcmpgt:
    case Hexagon::F2_dfcmpuo: {
      switch (OpNum) {
      case 1:
        // op: Rss32
        return 16;
      case 2:
        // op: Rtt32
        return 8;
      case 0:
        // op: Pd4
        return 0;
      }
      break;
    }
    case Hexagon::A5_vaddhubs:
    case Hexagon::M2_vdmpyrs_s0:
    case Hexagon::M2_vdmpyrs_s1:
    case Hexagon::M2_vraddh:
    case Hexagon::M2_vradduh:
    case Hexagon::M2_vrcmpys_s1rp_h:
    case Hexagon::M2_vrcmpys_s1rp_l:
    case Hexagon::M7_wcmpyiw:
    case Hexagon::M7_wcmpyiw_rnd:
    case Hexagon::M7_wcmpyiwc:
    case Hexagon::M7_wcmpyiwc_rnd:
    case Hexagon::M7_wcmpyrw:
    case Hexagon::M7_wcmpyrw_rnd:
    case Hexagon::M7_wcmpyrwc:
    case Hexagon::M7_wcmpyrwc_rnd:
    case Hexagon::S2_parityp: {
      switch (OpNum) {
      case 1:
        // op: Rss32
        return 16;
      case 2:
        // op: Rtt32
        return 8;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::A2_addp:
    case Hexagon::A2_addpsat:
    case Hexagon::A2_addsph:
    case Hexagon::A2_addspl:
    case Hexagon::A2_andp:
    case Hexagon::A2_maxp:
    case Hexagon::A2_maxup:
    case Hexagon::A2_orp:
    case Hexagon::A2_vaddh:
    case Hexagon::A2_vaddhs:
    case Hexagon::A2_vaddub:
    case Hexagon::A2_vaddubs:
    case Hexagon::A2_vadduhs:
    case Hexagon::A2_vaddw:
    case Hexagon::A2_vaddws:
    case Hexagon::A2_vavgh:
    case Hexagon::A2_vavghcr:
    case Hexagon::A2_vavghr:
    case Hexagon::A2_vavgub:
    case Hexagon::A2_vavgubr:
    case Hexagon::A2_vavguh:
    case Hexagon::A2_vavguhr:
    case Hexagon::A2_vavguw:
    case Hexagon::A2_vavguwr:
    case Hexagon::A2_vavgw:
    case Hexagon::A2_vavgwcr:
    case Hexagon::A2_vavgwr:
    case Hexagon::A2_vraddub:
    case Hexagon::A2_vrsadub:
    case Hexagon::A2_xorp:
    case Hexagon::F2_dfadd:
    case Hexagon::F2_dfmax:
    case Hexagon::F2_dfmin:
    case Hexagon::F2_dfmpyfix:
    case Hexagon::F2_dfmpyll:
    case Hexagon::F2_dfsub:
    case Hexagon::M2_mmpyh_rs0:
    case Hexagon::M2_mmpyh_rs1:
    case Hexagon::M2_mmpyh_s0:
    case Hexagon::M2_mmpyh_s1:
    case Hexagon::M2_mmpyl_rs0:
    case Hexagon::M2_mmpyl_rs1:
    case Hexagon::M2_mmpyl_s0:
    case Hexagon::M2_mmpyl_s1:
    case Hexagon::M2_mmpyuh_rs0:
    case Hexagon::M2_mmpyuh_rs1:
    case Hexagon::M2_mmpyuh_s0:
    case Hexagon::M2_mmpyuh_s1:
    case Hexagon::M2_mmpyul_rs0:
    case Hexagon::M2_mmpyul_rs1:
    case Hexagon::M2_mmpyul_s0:
    case Hexagon::M2_mmpyul_s1:
    case Hexagon::M2_vcmpy_s0_sat_i:
    case Hexagon::M2_vcmpy_s0_sat_r:
    case Hexagon::M2_vcmpy_s1_sat_i:
    case Hexagon::M2_vcmpy_s1_sat_r:
    case Hexagon::M2_vdmpys_s0:
    case Hexagon::M2_vdmpys_s1:
    case Hexagon::M2_vmpy2es_s0:
    case Hexagon::M2_vmpy2es_s1:
    case Hexagon::M2_vrcmpyi_s0:
    case Hexagon::M2_vrcmpyi_s0c:
    case Hexagon::M2_vrcmpyr_s0:
    case Hexagon::M2_vrcmpyr_s0c:
    case Hexagon::M2_vrcmpys_s1_h:
    case Hexagon::M2_vrcmpys_s1_l:
    case Hexagon::M2_vrmpy_s0:
    case Hexagon::M4_vrmpyeh_s0:
    case Hexagon::M4_vrmpyeh_s1:
    case Hexagon::M4_vrmpyoh_s0:
    case Hexagon::M4_vrmpyoh_s1:
    case Hexagon::M5_vdmpybsu:
    case Hexagon::M5_vrmpybsu:
    case Hexagon::M5_vrmpybuu:
    case Hexagon::M7_dcmpyiw:
    case Hexagon::M7_dcmpyiwc:
    case Hexagon::M7_dcmpyrw:
    case Hexagon::M7_dcmpyrwc:
    case Hexagon::S2_cabacdecbin:
    case Hexagon::S2_extractup_rp:
    case Hexagon::S2_lfsp:
    case Hexagon::S2_shuffeb:
    case Hexagon::S2_shuffeh:
    case Hexagon::S2_vtrunewh:
    case Hexagon::S2_vtrunowh:
    case Hexagon::S4_extractp_rp:
    case Hexagon::S4_vxaddsubh:
    case Hexagon::S4_vxaddsubhr:
    case Hexagon::S4_vxaddsubw:
    case Hexagon::S4_vxsubaddh:
    case Hexagon::S4_vxsubaddhr:
    case Hexagon::S4_vxsubaddw:
    case Hexagon::S6_vtrunehb_ppp:
    case Hexagon::S6_vtrunohb_ppp: {
      switch (OpNum) {
      case 1:
        // op: Rss32
        return 16;
      case 2:
        // op: Rtt32
        return 8;
      case 0:
        // op: Rdd32
        return 0;
      }
      break;
    }
    case Hexagon::S2_vsplicerb: {
      switch (OpNum) {
      case 1:
        // op: Rss32
        return 16;
      case 2:
        // op: Rtt32
        return 8;
      case 3:
        // op: Pu4
        return 5;
      case 0:
        // op: Rdd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_pred_scalar2:
    case Hexagon::V6_pred_scalar2v2: {
      switch (OpNum) {
      case 1:
        // op: Rt32
        return 16;
      case 0:
        // op: Qd4
        return 0;
      }
      break;
    }
    case Hexagon::V6_lvsplatb:
    case Hexagon::V6_lvsplath:
    case Hexagon::V6_lvsplatw:
    case Hexagon::V6_zextract: {
      switch (OpNum) {
      case 1:
        // op: Rt32
        return 16;
      case 0:
        // op: Vd32
        return 0;
      }
      break;
    }
    case Hexagon::A2_addh_h16_hh:
    case Hexagon::A2_addh_h16_hl:
    case Hexagon::A2_addh_h16_lh:
    case Hexagon::A2_addh_h16_ll:
    case Hexagon::A2_addh_h16_sat_hh:
    case Hexagon::A2_addh_h16_sat_hl:
    case Hexagon::A2_addh_h16_sat_lh:
    case Hexagon::A2_addh_h16_sat_ll:
    case Hexagon::A2_addh_l16_hl:
    case Hexagon::A2_addh_l16_ll:
    case Hexagon::A2_addh_l16_sat_hl:
    case Hexagon::A2_addh_l16_sat_ll:
    case Hexagon::A2_combine_hh:
    case Hexagon::A2_combine_hl:
    case Hexagon::A2_combine_lh:
    case Hexagon::A2_combine_ll:
    case Hexagon::A2_min:
    case Hexagon::A2_minu:
    case Hexagon::A2_sub:
    case Hexagon::A2_subh_h16_hh:
    case Hexagon::A2_subh_h16_hl:
    case Hexagon::A2_subh_h16_lh:
    case Hexagon::A2_subh_h16_ll:
    case Hexagon::A2_subh_h16_sat_hh:
    case Hexagon::A2_subh_h16_sat_hl:
    case Hexagon::A2_subh_h16_sat_lh:
    case Hexagon::A2_subh_h16_sat_ll:
    case Hexagon::A2_subh_l16_hl:
    case Hexagon::A2_subh_l16_ll:
    case Hexagon::A2_subh_l16_sat_hl:
    case Hexagon::A2_subh_l16_sat_ll:
    case Hexagon::A2_subsat:
    case Hexagon::A2_svnavgh:
    case Hexagon::A2_svsubh:
    case Hexagon::A2_svsubhs:
    case Hexagon::A2_svsubuhs:
    case Hexagon::A4_andn:
    case Hexagon::A4_orn:
    case Hexagon::dep_A2_subsat: {
      switch (OpNum) {
      case 1:
        // op: Rt32
        return 8;
      case 2:
        // op: Rs32
        return 16;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::A2_minp:
    case Hexagon::A2_minup:
    case Hexagon::A2_subp:
    case Hexagon::A2_vmaxb:
    case Hexagon::A2_vmaxh:
    case Hexagon::A2_vmaxub:
    case Hexagon::A2_vmaxuh:
    case Hexagon::A2_vmaxuw:
    case Hexagon::A2_vmaxw:
    case Hexagon::A2_vminb:
    case Hexagon::A2_vminh:
    case Hexagon::A2_vminub:
    case Hexagon::A2_vminuh:
    case Hexagon::A2_vminuw:
    case Hexagon::A2_vminw:
    case Hexagon::A2_vnavgh:
    case Hexagon::A2_vnavghcr:
    case Hexagon::A2_vnavghr:
    case Hexagon::A2_vnavgw:
    case Hexagon::A2_vnavgwcr:
    case Hexagon::A2_vnavgwr:
    case Hexagon::A2_vsubh:
    case Hexagon::A2_vsubhs:
    case Hexagon::A2_vsubub:
    case Hexagon::A2_vsububs:
    case Hexagon::A2_vsubuhs:
    case Hexagon::A2_vsubw:
    case Hexagon::A2_vsubws:
    case Hexagon::A4_andnp:
    case Hexagon::A4_ornp:
    case Hexagon::M2_vabsdiffh:
    case Hexagon::M2_vabsdiffw:
    case Hexagon::M6_vabsdiffb:
    case Hexagon::M6_vabsdiffub:
    case Hexagon::S2_shuffob:
    case Hexagon::S2_shuffoh: {
      switch (OpNum) {
      case 1:
        // op: Rtt32
        return 8;
      case 2:
        // op: Rss32
        return 16;
      case 0:
        // op: Rdd32
        return 0;
      }
      break;
    }
    case Hexagon::S2_valignrb: {
      switch (OpNum) {
      case 1:
        // op: Rtt32
        return 8;
      case 2:
        // op: Rss32
        return 16;
      case 3:
        // op: Pu4
        return 5;
      case 0:
        // op: Rdd32
        return 0;
      }
      break;
    }
    case Hexagon::M4_mpyrr_addr: {
      switch (OpNum) {
      case 1:
        // op: Ru32
        return 0;
      case 3:
        // op: Rs32
        return 16;
      case 0:
        // op: Ry32
        return 8;
      }
      break;
    }
    case Hexagon::Y2_tfrscrr: {
      switch (OpNum) {
      case 1:
        // op: Ss128
        return 16;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::Y4_tfrscpp: {
      switch (OpNum) {
      case 1:
        // op: Sss128
        return 16;
      case 0:
        // op: Rdd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vabs_f8:
    case Hexagon::V6_vabs_hf:
    case Hexagon::V6_vabs_qf16_hf:
    case Hexagon::V6_vabs_qf16_qf16:
    case Hexagon::V6_vabs_qf32_qf32:
    case Hexagon::V6_vabs_qf32_sf:
    case Hexagon::V6_vabs_sf:
    case Hexagon::V6_vabsb:
    case Hexagon::V6_vabsb_sat:
    case Hexagon::V6_vabsh:
    case Hexagon::V6_vabsh_sat:
    case Hexagon::V6_vabsw:
    case Hexagon::V6_vabsw_sat:
    case Hexagon::V6_vassign:
    case Hexagon::V6_vassign_fp:
    case Hexagon::V6_vassign_tmp:
    case Hexagon::V6_vcl0h:
    case Hexagon::V6_vcl0w:
    case Hexagon::V6_vconv_f8_qf16:
    case Hexagon::V6_vconv_h_hf:
    case Hexagon::V6_vconv_h_hf_rnd:
    case Hexagon::V6_vconv_hf_h:
    case Hexagon::V6_vconv_hf_qf16:
    case Hexagon::V6_vconv_qf16_hf:
    case Hexagon::V6_vconv_qf16_qf16:
    case Hexagon::V6_vconv_qf32_qf32:
    case Hexagon::V6_vconv_qf32_sf:
    case Hexagon::V6_vconv_sf_qf32:
    case Hexagon::V6_vconv_sf_w:
    case Hexagon::V6_vconv_w_sf:
    case Hexagon::V6_vcvt_h_hf:
    case Hexagon::V6_vcvt_hf_h:
    case Hexagon::V6_vcvt_hf_uh:
    case Hexagon::V6_vcvt_uh_hf:
    case Hexagon::V6_vdealb:
    case Hexagon::V6_vdealh:
    case Hexagon::V6_vfneg_f8:
    case Hexagon::V6_vfneg_hf:
    case Hexagon::V6_vfneg_sf:
    case Hexagon::V6_vilog2_hf:
    case Hexagon::V6_vilog2_qf16:
    case Hexagon::V6_vilog2_qf32:
    case Hexagon::V6_vilog2_sf:
    case Hexagon::V6_vneg_qf16_hf:
    case Hexagon::V6_vneg_qf16_qf16:
    case Hexagon::V6_vneg_qf32_qf32:
    case Hexagon::V6_vneg_qf32_sf:
    case Hexagon::V6_vnormamth:
    case Hexagon::V6_vnormamtw:
    case Hexagon::V6_vnot:
    case Hexagon::V6_vpopcounth:
    case Hexagon::V6_vshuffb:
    case Hexagon::V6_vshuffh: {
      switch (OpNum) {
      case 1:
        // op: Vu32
        return 8;
      case 0:
        // op: Vd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vconv_qf16_f8:
    case Hexagon::V6_vcvt2_hf_b:
    case Hexagon::V6_vcvt2_hf_ub:
    case Hexagon::V6_vcvt_hf_b:
    case Hexagon::V6_vcvt_hf_f8:
    case Hexagon::V6_vcvt_hf_ub:
    case Hexagon::V6_vcvt_sf_hf:
    case Hexagon::V6_vsb:
    case Hexagon::V6_vsh:
    case Hexagon::V6_vunpackb:
    case Hexagon::V6_vunpackh:
    case Hexagon::V6_vunpackub:
    case Hexagon::V6_vunpackuh:
    case Hexagon::V6_vzb:
    case Hexagon::V6_vzh: {
      switch (OpNum) {
      case 1:
        // op: Vu32
        return 8;
      case 0:
        // op: Vdd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_extractw: {
      switch (OpNum) {
      case 1:
        // op: Vu32
        return 8;
      case 2:
        // op: Rs32
        return 16;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vandvrt: {
      switch (OpNum) {
      case 1:
        // op: Vu32
        return 8;
      case 2:
        // op: Rt32
        return 16;
      case 0:
        // op: Qd4
        return 0;
      }
      break;
    }
    case Hexagon::V6_get_qfext:
    case Hexagon::V6_set_qfext:
    case Hexagon::V6_vaslh:
    case Hexagon::V6_vaslw:
    case Hexagon::V6_vasrh:
    case Hexagon::V6_vasrw:
    case Hexagon::V6_vdmpybus:
    case Hexagon::V6_vdmpyhb:
    case Hexagon::V6_vdmpyhsat:
    case Hexagon::V6_vdmpyhsusat:
    case Hexagon::V6_vlsrb:
    case Hexagon::V6_vlsrh:
    case Hexagon::V6_vlsrw:
    case Hexagon::V6_vmpy_rt_hf:
    case Hexagon::V6_vmpy_rt_qf16:
    case Hexagon::V6_vmpy_rt_sf:
    case Hexagon::V6_vmpyhsrs:
    case Hexagon::V6_vmpyhss:
    case Hexagon::V6_vmpyihb:
    case Hexagon::V6_vmpyiwb:
    case Hexagon::V6_vmpyiwh:
    case Hexagon::V6_vmpyiwub:
    case Hexagon::V6_vmpyuhe:
    case Hexagon::V6_vrmpybus:
    case Hexagon::V6_vrmpyub:
    case Hexagon::V6_vror: {
      switch (OpNum) {
      case 1:
        // op: Vu32
        return 8;
      case 2:
        // op: Rt32
        return 16;
      case 0:
        // op: Vd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vmpybus:
    case Hexagon::V6_vmpyh:
    case Hexagon::V6_vmpyub:
    case Hexagon::V6_vmpyuh: {
      switch (OpNum) {
      case 1:
        // op: Vu32
        return 8;
      case 2:
        // op: Rt32
        return 16;
      case 0:
        // op: Vdd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vrmpyzbb_rt:
    case Hexagon::V6_vrmpyzbub_rt:
    case Hexagon::V6_vrmpyzcb_rt:
    case Hexagon::V6_vrmpyzcbs_rt:
    case Hexagon::V6_vrmpyznb_rt: {
      switch (OpNum) {
      case 1:
        // op: Vu32
        return 8;
      case 2:
        // op: Rt8
        return 16;
      case 0:
        // op: Vdddd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vlut4: {
      switch (OpNum) {
      case 1:
        // op: Vu32
        return 8;
      case 2:
        // op: Rtt32
        return 16;
      case 0:
        // op: Vd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vrmpybub_rtt:
    case Hexagon::V6_vrmpyub_rtt: {
      switch (OpNum) {
      case 1:
        // op: Vu32
        return 8;
      case 2:
        // op: Rtt32
        return 16;
      case 0:
        // op: Vdd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_veqb:
    case Hexagon::V6_veqh:
    case Hexagon::V6_veqhf:
    case Hexagon::V6_veqsf:
    case Hexagon::V6_veqw:
    case Hexagon::V6_vgtb:
    case Hexagon::V6_vgtbf:
    case Hexagon::V6_vgth:
    case Hexagon::V6_vgthf:
    case Hexagon::V6_vgtsf:
    case Hexagon::V6_vgtub:
    case Hexagon::V6_vgtuh:
    case Hexagon::V6_vgtuw:
    case Hexagon::V6_vgtw: {
      switch (OpNum) {
      case 1:
        // op: Vu32
        return 8;
      case 2:
        // op: Vv32
        return 16;
      case 0:
        // op: Qd4
        return 0;
      }
      break;
    }
    case Hexagon::V6_vabsdiffh:
    case Hexagon::V6_vabsdiffub:
    case Hexagon::V6_vabsdiffuh:
    case Hexagon::V6_vabsdiffw:
    case Hexagon::V6_vadd_hf:
    case Hexagon::V6_vadd_hf_hf:
    case Hexagon::V6_vadd_qf16:
    case Hexagon::V6_vadd_qf16_mix:
    case Hexagon::V6_vadd_qf32:
    case Hexagon::V6_vadd_qf32_mix:
    case Hexagon::V6_vadd_sf:
    case Hexagon::V6_vadd_sf_sf:
    case Hexagon::V6_vaddb:
    case Hexagon::V6_vaddbsat:
    case Hexagon::V6_vaddclbh:
    case Hexagon::V6_vaddclbw:
    case Hexagon::V6_vaddh:
    case Hexagon::V6_vaddhsat:
    case Hexagon::V6_vaddubsat:
    case Hexagon::V6_vaddububb_sat:
    case Hexagon::V6_vadduhsat:
    case Hexagon::V6_vadduwsat:
    case Hexagon::V6_vaddw:
    case Hexagon::V6_vaddwsat:
    case Hexagon::V6_vand:
    case Hexagon::V6_vaslhv:
    case Hexagon::V6_vaslwv:
    case Hexagon::V6_vasrhv:
    case Hexagon::V6_vasrwv:
    case Hexagon::V6_vavgb:
    case Hexagon::V6_vavgbrnd:
    case Hexagon::V6_vavgh:
    case Hexagon::V6_vavghrnd:
    case Hexagon::V6_vavgub:
    case Hexagon::V6_vavgubrnd:
    case Hexagon::V6_vavguh:
    case Hexagon::V6_vavguhrnd:
    case Hexagon::V6_vavguw:
    case Hexagon::V6_vavguwrnd:
    case Hexagon::V6_vavgw:
    case Hexagon::V6_vavgwrnd:
    case Hexagon::V6_vcvt2_b_hf:
    case Hexagon::V6_vcvt2_ub_hf:
    case Hexagon::V6_vcvt_b_hf:
    case Hexagon::V6_vcvt_bf_sf:
    case Hexagon::V6_vcvt_f8_hf:
    case Hexagon::V6_vcvt_hf_sf:
    case Hexagon::V6_vcvt_ub_hf:
    case Hexagon::V6_vdealb4w:
    case Hexagon::V6_vdelta:
    case Hexagon::V6_vdmpy_sf_hf:
    case Hexagon::V6_vdmpyhvsat:
    case Hexagon::V6_vfmax_f8:
    case Hexagon::V6_vfmax_hf:
    case Hexagon::V6_vfmax_sf:
    case Hexagon::V6_vfmin_f8:
    case Hexagon::V6_vfmin_hf:
    case Hexagon::V6_vfmin_sf:
    case Hexagon::V6_vlsrhv:
    case Hexagon::V6_vlsrwv:
    case Hexagon::V6_vmax_bf:
    case Hexagon::V6_vmax_hf:
    case Hexagon::V6_vmax_sf:
    case Hexagon::V6_vmaxb:
    case Hexagon::V6_vmaxh:
    case Hexagon::V6_vmaxub:
    case Hexagon::V6_vmaxuh:
    case Hexagon::V6_vmaxw:
    case Hexagon::V6_vmerge_qf:
    case Hexagon::V6_vmin_bf:
    case Hexagon::V6_vmin_hf:
    case Hexagon::V6_vmin_sf:
    case Hexagon::V6_vminb:
    case Hexagon::V6_vminh:
    case Hexagon::V6_vminub:
    case Hexagon::V6_vminuh:
    case Hexagon::V6_vminw:
    case Hexagon::V6_vmpy_hf_hf:
    case Hexagon::V6_vmpy_qf16:
    case Hexagon::V6_vmpy_qf16_hf:
    case Hexagon::V6_vmpy_qf16_mix_hf:
    case Hexagon::V6_vmpy_qf32:
    case Hexagon::V6_vmpy_qf32_sf:
    case Hexagon::V6_vmpy_sf_sf:
    case Hexagon::V6_vmpyewuh:
    case Hexagon::V6_vmpyhvsrs:
    case Hexagon::V6_vmpyieoh:
    case Hexagon::V6_vmpyiewuh:
    case Hexagon::V6_vmpyih:
    case Hexagon::V6_vmpyiowh:
    case Hexagon::V6_vmpyowh:
    case Hexagon::V6_vmpyowh_rnd:
    case Hexagon::V6_vmpyuhvs:
    case Hexagon::V6_vnavgb:
    case Hexagon::V6_vnavgh:
    case Hexagon::V6_vnavgub:
    case Hexagon::V6_vnavgw:
    case Hexagon::V6_vor:
    case Hexagon::V6_vpackeb:
    case Hexagon::V6_vpackeh:
    case Hexagon::V6_vpackhb_sat:
    case Hexagon::V6_vpackhub_sat:
    case Hexagon::V6_vpackob:
    case Hexagon::V6_vpackoh:
    case Hexagon::V6_vpackwh_sat:
    case Hexagon::V6_vpackwuh_sat:
    case Hexagon::V6_vrdelta:
    case Hexagon::V6_vrmpybusv:
    case Hexagon::V6_vrmpybv:
    case Hexagon::V6_vrmpyubv:
    case Hexagon::V6_vrotr:
    case Hexagon::V6_vroundhb:
    case Hexagon::V6_vroundhub:
    case Hexagon::V6_vrounduhub:
    case Hexagon::V6_vrounduwuh:
    case Hexagon::V6_vroundwh:
    case Hexagon::V6_vroundwuh:
    case Hexagon::V6_vsatdw:
    case Hexagon::V6_vsathub:
    case Hexagon::V6_vsatuwuh:
    case Hexagon::V6_vsatwh:
    case Hexagon::V6_vshufeh:
    case Hexagon::V6_vshuffeb:
    case Hexagon::V6_vshuffob:
    case Hexagon::V6_vshufoh:
    case Hexagon::V6_vsub_hf:
    case Hexagon::V6_vsub_hf_hf:
    case Hexagon::V6_vsub_hf_mix:
    case Hexagon::V6_vsub_qf16:
    case Hexagon::V6_vsub_qf16_mix:
    case Hexagon::V6_vsub_qf32:
    case Hexagon::V6_vsub_qf32_mix:
    case Hexagon::V6_vsub_sf:
    case Hexagon::V6_vsub_sf_mix:
    case Hexagon::V6_vsub_sf_sf:
    case Hexagon::V6_vsubb:
    case Hexagon::V6_vsubbsat:
    case Hexagon::V6_vsubh:
    case Hexagon::V6_vsubhsat:
    case Hexagon::V6_vsububsat:
    case Hexagon::V6_vsubububb_sat:
    case Hexagon::V6_vsubuhsat:
    case Hexagon::V6_vsubuwsat:
    case Hexagon::V6_vsubw:
    case Hexagon::V6_vsubwsat:
    case Hexagon::V6_vxor: {
      switch (OpNum) {
      case 1:
        // op: Vu32
        return 8;
      case 2:
        // op: Vv32
        return 16;
      case 0:
        // op: Vd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vadd_hf_f8:
    case Hexagon::V6_vadd_sf_bf:
    case Hexagon::V6_vadd_sf_hf:
    case Hexagon::V6_vaddhw:
    case Hexagon::V6_vaddubh:
    case Hexagon::V6_vadduhw:
    case Hexagon::V6_vcombine:
    case Hexagon::V6_vcombine_tmp:
    case Hexagon::V6_vmpy_hf_f8:
    case Hexagon::V6_vmpy_qf32_hf:
    case Hexagon::V6_vmpy_qf32_mix_hf:
    case Hexagon::V6_vmpy_qf32_qf16:
    case Hexagon::V6_vmpy_sf_bf:
    case Hexagon::V6_vmpy_sf_hf:
    case Hexagon::V6_vmpybusv:
    case Hexagon::V6_vmpybv:
    case Hexagon::V6_vmpyewuh_64:
    case Hexagon::V6_vmpyhus:
    case Hexagon::V6_vmpyhv:
    case Hexagon::V6_vmpyubv:
    case Hexagon::V6_vmpyuhv:
    case Hexagon::V6_vshufoeb:
    case Hexagon::V6_vshufoeh:
    case Hexagon::V6_vsub_hf_f8:
    case Hexagon::V6_vsub_sf_bf:
    case Hexagon::V6_vsub_sf_hf:
    case Hexagon::V6_vsubhw:
    case Hexagon::V6_vsububh:
    case Hexagon::V6_vsubuhw: {
      switch (OpNum) {
      case 1:
        // op: Vu32
        return 8;
      case 2:
        // op: Vv32
        return 16;
      case 0:
        // op: Vdd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vaddcarrysat: {
      switch (OpNum) {
      case 1:
        // op: Vu32
        return 8;
      case 2:
        // op: Vv32
        return 16;
      case 3:
        // op: Qs4
        return 5;
      case 0:
        // op: Vd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_valign4:
    case Hexagon::V6_valignb:
    case Hexagon::V6_vasrhbrndsat:
    case Hexagon::V6_vasrhbsat:
    case Hexagon::V6_vasrhubrndsat:
    case Hexagon::V6_vasrhubsat:
    case Hexagon::V6_vasruhubrndsat:
    case Hexagon::V6_vasruhubsat:
    case Hexagon::V6_vasruwuhrndsat:
    case Hexagon::V6_vasruwuhsat:
    case Hexagon::V6_vasrwh:
    case Hexagon::V6_vasrwhrndsat:
    case Hexagon::V6_vasrwhsat:
    case Hexagon::V6_vasrwuhrndsat:
    case Hexagon::V6_vasrwuhsat:
    case Hexagon::V6_vlalignb:
    case Hexagon::V6_vlutvvb:
    case Hexagon::V6_vlutvvb_nm: {
      switch (OpNum) {
      case 1:
        // op: Vu32
        return 8;
      case 2:
        // op: Vv32
        return 19;
      case 3:
        // op: Rt8
        return 16;
      case 0:
        // op: Vd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vdealvdd:
    case Hexagon::V6_vlutvwh:
    case Hexagon::V6_vlutvwh_nm:
    case Hexagon::V6_vshuffvdd: {
      switch (OpNum) {
      case 1:
        // op: Vu32
        return 8;
      case 2:
        // op: Vv32
        return 19;
      case 3:
        // op: Rt8
        return 16;
      case 0:
        // op: Vdd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vconv_bf_qf32:
    case Hexagon::V6_vconv_hf_qf32: {
      switch (OpNum) {
      case 1:
        // op: Vuu32
        return 8;
      case 0:
        // op: Vd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vdmpyhisat:
    case Hexagon::V6_vdmpyhsuisat: {
      switch (OpNum) {
      case 1:
        // op: Vuu32
        return 8;
      case 2:
        // op: Rt32
        return 16;
      case 0:
        // op: Vd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vdmpybus_dv:
    case Hexagon::V6_vdmpyhb_dv:
    case Hexagon::V6_vdsaduh:
    case Hexagon::V6_vmpabus:
    case Hexagon::V6_vmpabuu:
    case Hexagon::V6_vmpahb:
    case Hexagon::V6_vmpauhb:
    case Hexagon::V6_vtmpyb:
    case Hexagon::V6_vtmpybus:
    case Hexagon::V6_vtmpyhb: {
      switch (OpNum) {
      case 1:
        // op: Vuu32
        return 8;
      case 2:
        // op: Rt32
        return 16;
      case 0:
        // op: Vdd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vasrvuhubrndsat:
    case Hexagon::V6_vasrvuhubsat:
    case Hexagon::V6_vasrvwuhrndsat:
    case Hexagon::V6_vasrvwuhsat: {
      switch (OpNum) {
      case 1:
        // op: Vuu32
        return 8;
      case 2:
        // op: Vv32
        return 16;
      case 0:
        // op: Vd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vaddb_dv:
    case Hexagon::V6_vaddbsat_dv:
    case Hexagon::V6_vaddh_dv:
    case Hexagon::V6_vaddhsat_dv:
    case Hexagon::V6_vaddubsat_dv:
    case Hexagon::V6_vadduhsat_dv:
    case Hexagon::V6_vadduwsat_dv:
    case Hexagon::V6_vaddw_dv:
    case Hexagon::V6_vaddwsat_dv:
    case Hexagon::V6_vmpabusv:
    case Hexagon::V6_vmpabuuv:
    case Hexagon::V6_vsubb_dv:
    case Hexagon::V6_vsubbsat_dv:
    case Hexagon::V6_vsubh_dv:
    case Hexagon::V6_vsubhsat_dv:
    case Hexagon::V6_vsububsat_dv:
    case Hexagon::V6_vsubuhsat_dv:
    case Hexagon::V6_vsubuwsat_dv:
    case Hexagon::V6_vsubw_dv:
    case Hexagon::V6_vsubwsat_dv: {
      switch (OpNum) {
      case 1:
        // op: Vuu32
        return 8;
      case 2:
        // op: Vvv32
        return 16;
      case 0:
        // op: Vdd32
        return 0;
      }
      break;
    }
    case Hexagon::L4_loadbsw2_ap:
    case Hexagon::L4_loadbzw2_ap:
    case Hexagon::L4_loadrb_ap:
    case Hexagon::L4_loadrh_ap:
    case Hexagon::L4_loadri_ap:
    case Hexagon::L4_loadrub_ap:
    case Hexagon::L4_loadruh_ap: {
      switch (OpNum) {
      case 2:
        // op: II
        return 5;
      case 0:
        // op: Rd32
        return 0;
      case 1:
        // op: Re32
        return 16;
      }
      break;
    }
    case Hexagon::L4_loadbsw4_ap:
    case Hexagon::L4_loadbzw4_ap:
    case Hexagon::L4_loadrd_ap: {
      switch (OpNum) {
      case 2:
        // op: II
        return 5;
      case 0:
        // op: Rdd32
        return 0;
      case 1:
        // op: Re32
        return 16;
      }
      break;
    }
    case Hexagon::A2_tfrih:
    case Hexagon::A2_tfril:
    case Hexagon::S2_allocframe: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 0;
      case 0:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::J4_cmpeq_f_jumpnv_nt:
    case Hexagon::J4_cmpeq_f_jumpnv_t:
    case Hexagon::J4_cmpeq_t_jumpnv_nt:
    case Hexagon::J4_cmpeq_t_jumpnv_t:
    case Hexagon::J4_cmpgt_f_jumpnv_nt:
    case Hexagon::J4_cmpgt_f_jumpnv_t:
    case Hexagon::J4_cmpgt_t_jumpnv_nt:
    case Hexagon::J4_cmpgt_t_jumpnv_t:
    case Hexagon::J4_cmpgtu_f_jumpnv_nt:
    case Hexagon::J4_cmpgtu_f_jumpnv_t:
    case Hexagon::J4_cmpgtu_t_jumpnv_nt:
    case Hexagon::J4_cmpgtu_t_jumpnv_t: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 1;
      case 0:
        // op: Ns8
        return 16;
      case 1:
        // op: Rt32
        return 8;
      }
      break;
    }
    case Hexagon::J4_cmpeqn1_f_jumpnv_nt:
    case Hexagon::J4_cmpeqn1_f_jumpnv_t:
    case Hexagon::J4_cmpeqn1_t_jumpnv_nt:
    case Hexagon::J4_cmpeqn1_t_jumpnv_t:
    case Hexagon::J4_cmpgtn1_f_jumpnv_nt:
    case Hexagon::J4_cmpgtn1_f_jumpnv_t:
    case Hexagon::J4_cmpgtn1_t_jumpnv_nt:
    case Hexagon::J4_cmpgtn1_t_jumpnv_t: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 1;
      case 0:
        // op: Ns8
        return 16;
      }
      break;
    }
    case Hexagon::J4_cmpeq_fp0_jump_nt:
    case Hexagon::J4_cmpeq_fp0_jump_t:
    case Hexagon::J4_cmpeq_fp1_jump_nt:
    case Hexagon::J4_cmpeq_fp1_jump_t:
    case Hexagon::J4_cmpeq_tp0_jump_nt:
    case Hexagon::J4_cmpeq_tp0_jump_t:
    case Hexagon::J4_cmpeq_tp1_jump_nt:
    case Hexagon::J4_cmpeq_tp1_jump_t:
    case Hexagon::J4_cmpgt_fp0_jump_nt:
    case Hexagon::J4_cmpgt_fp0_jump_t:
    case Hexagon::J4_cmpgt_fp1_jump_nt:
    case Hexagon::J4_cmpgt_fp1_jump_t:
    case Hexagon::J4_cmpgt_tp0_jump_nt:
    case Hexagon::J4_cmpgt_tp0_jump_t:
    case Hexagon::J4_cmpgt_tp1_jump_nt:
    case Hexagon::J4_cmpgt_tp1_jump_t:
    case Hexagon::J4_cmpgtu_fp0_jump_nt:
    case Hexagon::J4_cmpgtu_fp0_jump_t:
    case Hexagon::J4_cmpgtu_fp1_jump_nt:
    case Hexagon::J4_cmpgtu_fp1_jump_t:
    case Hexagon::J4_cmpgtu_tp0_jump_nt:
    case Hexagon::J4_cmpgtu_tp0_jump_t:
    case Hexagon::J4_cmpgtu_tp1_jump_nt:
    case Hexagon::J4_cmpgtu_tp1_jump_t: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 1;
      case 0:
        // op: Rs16
        return 16;
      case 1:
        // op: Rt16
        return 8;
      }
      break;
    }
    case Hexagon::J4_cmpeqn1_fp0_jump_nt:
    case Hexagon::J4_cmpeqn1_fp0_jump_t:
    case Hexagon::J4_cmpeqn1_fp1_jump_nt:
    case Hexagon::J4_cmpeqn1_fp1_jump_t:
    case Hexagon::J4_cmpeqn1_tp0_jump_nt:
    case Hexagon::J4_cmpeqn1_tp0_jump_t:
    case Hexagon::J4_cmpeqn1_tp1_jump_nt:
    case Hexagon::J4_cmpeqn1_tp1_jump_t:
    case Hexagon::J4_cmpgtn1_fp0_jump_nt:
    case Hexagon::J4_cmpgtn1_fp0_jump_t:
    case Hexagon::J4_cmpgtn1_fp1_jump_nt:
    case Hexagon::J4_cmpgtn1_fp1_jump_t:
    case Hexagon::J4_cmpgtn1_tp0_jump_nt:
    case Hexagon::J4_cmpgtn1_tp0_jump_t:
    case Hexagon::J4_cmpgtn1_tp1_jump_nt:
    case Hexagon::J4_cmpgtn1_tp1_jump_t: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 1;
      case 0:
        // op: Rs16
        return 16;
      }
      break;
    }
    case Hexagon::J4_cmplt_f_jumpnv_nt:
    case Hexagon::J4_cmplt_f_jumpnv_t:
    case Hexagon::J4_cmplt_t_jumpnv_nt:
    case Hexagon::J4_cmplt_t_jumpnv_t:
    case Hexagon::J4_cmpltu_f_jumpnv_nt:
    case Hexagon::J4_cmpltu_f_jumpnv_t:
    case Hexagon::J4_cmpltu_t_jumpnv_nt:
    case Hexagon::J4_cmpltu_t_jumpnv_t: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 1;
      case 0:
        // op: Rt32
        return 8;
      case 1:
        // op: Ns8
        return 16;
      }
      break;
    }
    case Hexagon::J4_jumpsetr: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 1;
      case 1:
        // op: Rs16
        return 16;
      case 0:
        // op: Rd16
        return 8;
      }
      break;
    }
    case Hexagon::J2_trap1: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 2;
      case 0:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::S2_pstorerbnewf_io:
    case Hexagon::S2_pstorerbnewt_io:
    case Hexagon::S2_pstorerhnewf_io:
    case Hexagon::S2_pstorerhnewt_io:
    case Hexagon::S2_pstorerinewf_io:
    case Hexagon::S2_pstorerinewt_io:
    case Hexagon::S4_pstorerbnewfnew_io:
    case Hexagon::S4_pstorerbnewtnew_io:
    case Hexagon::S4_pstorerhnewfnew_io:
    case Hexagon::S4_pstorerhnewtnew_io:
    case Hexagon::S4_pstorerinewfnew_io:
    case Hexagon::S4_pstorerinewtnew_io: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 3;
      case 0:
        // op: Pv4
        return 0;
      case 1:
        // op: Rs32
        return 16;
      case 3:
        // op: Nt8
        return 8;
      }
      break;
    }
    case Hexagon::S2_pstorerbf_io:
    case Hexagon::S2_pstorerbt_io:
    case Hexagon::S2_pstorerff_io:
    case Hexagon::S2_pstorerft_io:
    case Hexagon::S2_pstorerhf_io:
    case Hexagon::S2_pstorerht_io:
    case Hexagon::S2_pstorerif_io:
    case Hexagon::S2_pstorerit_io:
    case Hexagon::S4_pstorerbfnew_io:
    case Hexagon::S4_pstorerbtnew_io:
    case Hexagon::S4_pstorerffnew_io:
    case Hexagon::S4_pstorerftnew_io:
    case Hexagon::S4_pstorerhfnew_io:
    case Hexagon::S4_pstorerhtnew_io:
    case Hexagon::S4_pstorerifnew_io:
    case Hexagon::S4_pstoreritnew_io: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 3;
      case 0:
        // op: Pv4
        return 0;
      case 1:
        // op: Rs32
        return 16;
      case 3:
        // op: Rt32
        return 8;
      }
      break;
    }
    case Hexagon::S2_pstorerdf_io:
    case Hexagon::S2_pstorerdt_io:
    case Hexagon::S4_pstorerdfnew_io:
    case Hexagon::S4_pstorerdtnew_io: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 3;
      case 0:
        // op: Pv4
        return 0;
      case 1:
        // op: Rs32
        return 16;
      case 3:
        // op: Rtt32
        return 8;
      }
      break;
    }
    case Hexagon::S2_storerbnew_pci:
    case Hexagon::S2_storerhnew_pci:
    case Hexagon::S2_storerinew_pci: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 3;
      case 3:
        // op: Mu2
        return 13;
      case 4:
        // op: Nt8
        return 8;
      case 0:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::S2_storerb_pci:
    case Hexagon::S2_storerf_pci:
    case Hexagon::S2_storerh_pci:
    case Hexagon::S2_storeri_pci: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 3;
      case 3:
        // op: Mu2
        return 13;
      case 4:
        // op: Rt32
        return 8;
      case 0:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::S2_storerd_pci: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 3;
      case 3:
        // op: Mu2
        return 13;
      case 4:
        // op: Rtt32
        return 8;
      case 0:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::S2_storerbnew_pi:
    case Hexagon::S2_storerhnew_pi:
    case Hexagon::S2_storerinew_pi: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 3;
      case 3:
        // op: Nt8
        return 8;
      case 0:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::S2_storerb_pi:
    case Hexagon::S2_storerf_pi:
    case Hexagon::S2_storerh_pi:
    case Hexagon::S2_storeri_pi: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 3;
      case 3:
        // op: Rt32
        return 8;
      case 0:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::S2_storerd_pi: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 3;
      case 3:
        // op: Rtt32
        return 8;
      case 0:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::SA1_addi: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 4;
      case 0:
        // op: Rx16
        return 0;
      }
      break;
    }
    case Hexagon::C2_cmoveif:
    case Hexagon::C2_cmoveit:
    case Hexagon::C2_cmovenewif:
    case Hexagon::C2_cmovenewit: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 5;
      case 1:
        // op: Pu4
        return 21;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::C2_muxri: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 5;
      case 1:
        // op: Pu4
        return 21;
      case 3:
        // op: Rs32
        return 16;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::A4_cmpbeqi:
    case Hexagon::A4_cmpbgti:
    case Hexagon::A4_cmpbgtui:
    case Hexagon::A4_cmpheqi:
    case Hexagon::A4_cmphgti:
    case Hexagon::A4_cmphgtui:
    case Hexagon::C2_cmpeqi:
    case Hexagon::C2_cmpgti:
    case Hexagon::C2_cmpgtui:
    case Hexagon::C4_cmpltei:
    case Hexagon::C4_cmplteui:
    case Hexagon::C4_cmpneqi: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 5;
      case 1:
        // op: Rs32
        return 16;
      case 0:
        // op: Pd4
        return 0;
      }
      break;
    }
    case Hexagon::A2_addi:
    case Hexagon::A2_andir:
    case Hexagon::A2_orir:
    case Hexagon::A4_rcmpeqi:
    case Hexagon::A4_rcmpneqi:
    case Hexagon::L2_loadbsw2_io:
    case Hexagon::L2_loadbzw2_io:
    case Hexagon::L2_loadrb_io:
    case Hexagon::L2_loadrh_io:
    case Hexagon::L2_loadri_io:
    case Hexagon::L2_loadrub_io:
    case Hexagon::L2_loadruh_io:
    case Hexagon::M2_mpysin:
    case Hexagon::M2_mpysip: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 5;
      case 1:
        // op: Rs32
        return 16;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::A4_combineri:
    case Hexagon::L2_loadbsw4_io:
    case Hexagon::L2_loadbzw4_io:
    case Hexagon::L2_loadrd_io: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 5;
      case 1:
        // op: Rs32
        return 16;
      case 0:
        // op: Rdd32
        return 0;
      }
      break;
    }
    case Hexagon::S4_subaddi: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 5;
      case 1:
        // op: Rs32
        return 16;
      case 3:
        // op: Ru32
        return 0;
      case 0:
        // op: Rd32
        return 8;
      }
      break;
    }
    case Hexagon::A4_vcmpbeqi:
    case Hexagon::A4_vcmpbgti:
    case Hexagon::A4_vcmpbgtui:
    case Hexagon::A4_vcmpheqi:
    case Hexagon::A4_vcmphgti:
    case Hexagon::A4_vcmphgtui:
    case Hexagon::A4_vcmpweqi:
    case Hexagon::A4_vcmpwgti:
    case Hexagon::A4_vcmpwgtui:
    case Hexagon::F2_dfclass: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 5;
      case 1:
        // op: Rss32
        return 16;
      case 0:
        // op: Pd4
        return 0;
      }
      break;
    }
    case Hexagon::M4_mpyri_addr_u2: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 5;
      case 1:
        // op: Ru32
        return 0;
      case 3:
        // op: Rs32
        return 16;
      case 0:
        // op: Rd32
        return 8;
      }
      break;
    }
    case Hexagon::C2_muxii: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 5;
      case 3:
        // op: II
        return 13;
      case 1:
        // op: Pu4
        return 23;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::S4_storerbnew_rr:
    case Hexagon::S4_storerhnew_rr:
    case Hexagon::S4_storerinew_rr: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 7;
      case 0:
        // op: Rs32
        return 16;
      case 1:
        // op: Ru32
        return 8;
      case 3:
        // op: Nt8
        return 0;
      }
      break;
    }
    case Hexagon::S4_storerb_rr:
    case Hexagon::S4_storerf_rr:
    case Hexagon::S4_storerh_rr:
    case Hexagon::S4_storeri_rr: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 7;
      case 0:
        // op: Rs32
        return 16;
      case 1:
        // op: Ru32
        return 8;
      case 3:
        // op: Rt32
        return 0;
      }
      break;
    }
    case Hexagon::S4_storerd_rr: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 7;
      case 0:
        // op: Rs32
        return 16;
      case 1:
        // op: Ru32
        return 8;
      case 3:
        // op: Rtt32
        return 0;
      }
      break;
    }
    case Hexagon::S4_storeirbf_io:
    case Hexagon::S4_storeirbfnew_io:
    case Hexagon::S4_storeirbt_io:
    case Hexagon::S4_storeirbtnew_io:
    case Hexagon::S4_storeirhf_io:
    case Hexagon::S4_storeirhfnew_io:
    case Hexagon::S4_storeirht_io:
    case Hexagon::S4_storeirhtnew_io:
    case Hexagon::S4_storeirif_io:
    case Hexagon::S4_storeirifnew_io:
    case Hexagon::S4_storeirit_io:
    case Hexagon::S4_storeiritnew_io: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 7;
      case 3:
        // op: II
        return 0;
      case 0:
        // op: Pv4
        return 5;
      case 1:
        // op: Rs32
        return 16;
      }
      break;
    }
    case Hexagon::L4_loadbsw2_ur:
    case Hexagon::L4_loadbzw2_ur:
    case Hexagon::L4_loadrb_ur:
    case Hexagon::L4_loadrh_ur:
    case Hexagon::L4_loadri_ur:
    case Hexagon::L4_loadrub_ur:
    case Hexagon::L4_loadruh_ur: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 7;
      case 3:
        // op: II
        return 5;
      case 1:
        // op: Rt32
        return 16;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::L4_loadbsw4_ur:
    case Hexagon::L4_loadbzw4_ur:
    case Hexagon::L4_loadrd_ur: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 7;
      case 3:
        // op: II
        return 5;
      case 1:
        // op: Rt32
        return 16;
      case 0:
        // op: Rdd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vS32b_new_npred_ai:
    case Hexagon::V6_vS32b_new_pred_ai:
    case Hexagon::V6_vS32b_nt_new_npred_ai:
    case Hexagon::V6_vS32b_nt_new_pred_ai: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 8;
      case 0:
        // op: Pv4
        return 11;
      case 1:
        // op: Rt32
        return 16;
      case 3:
        // op: Os8
        return 0;
      }
      break;
    }
    case Hexagon::V6_vS32Ub_npred_ai:
    case Hexagon::V6_vS32Ub_pred_ai:
    case Hexagon::V6_vS32b_npred_ai:
    case Hexagon::V6_vS32b_nt_npred_ai:
    case Hexagon::V6_vS32b_nt_pred_ai:
    case Hexagon::V6_vS32b_pred_ai: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 8;
      case 0:
        // op: Pv4
        return 11;
      case 1:
        // op: Rt32
        return 16;
      case 3:
        // op: Vs32
        return 0;
      }
      break;
    }
    case Hexagon::V6_zLd_pred_ai: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 8;
      case 0:
        // op: Pv4
        return 11;
      case 1:
        // op: Rt32
        return 16;
      }
      break;
    }
    case Hexagon::V6_vS32b_nqpred_ai:
    case Hexagon::V6_vS32b_nt_nqpred_ai:
    case Hexagon::V6_vS32b_nt_qpred_ai:
    case Hexagon::V6_vS32b_qpred_ai: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 8;
      case 0:
        // op: Qv4
        return 11;
      case 1:
        // op: Rt32
        return 16;
      case 3:
        // op: Vs32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vS32b_srls_pi:
    case Hexagon::V6_zLd_pi: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 8;
      case 0:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::L4_ploadrbf_abs:
    case Hexagon::L4_ploadrbfnew_abs:
    case Hexagon::L4_ploadrbt_abs:
    case Hexagon::L4_ploadrbtnew_abs:
    case Hexagon::L4_ploadrhf_abs:
    case Hexagon::L4_ploadrhfnew_abs:
    case Hexagon::L4_ploadrht_abs:
    case Hexagon::L4_ploadrhtnew_abs:
    case Hexagon::L4_ploadrif_abs:
    case Hexagon::L4_ploadrifnew_abs:
    case Hexagon::L4_ploadrit_abs:
    case Hexagon::L4_ploadritnew_abs:
    case Hexagon::L4_ploadrubf_abs:
    case Hexagon::L4_ploadrubfnew_abs:
    case Hexagon::L4_ploadrubt_abs:
    case Hexagon::L4_ploadrubtnew_abs:
    case Hexagon::L4_ploadruhf_abs:
    case Hexagon::L4_ploadruhfnew_abs:
    case Hexagon::L4_ploadruht_abs:
    case Hexagon::L4_ploadruhtnew_abs: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 8;
      case 1:
        // op: Pt4
        return 9;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::L4_ploadrdf_abs:
    case Hexagon::L4_ploadrdfnew_abs:
    case Hexagon::L4_ploadrdt_abs:
    case Hexagon::L4_ploadrdtnew_abs: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 8;
      case 1:
        // op: Pt4
        return 9;
      case 0:
        // op: Rdd32
        return 0;
      }
      break;
    }
    case Hexagon::SL1_loadri_io:
    case Hexagon::SL1_loadrub_io:
    case Hexagon::SL2_loadrb_io:
    case Hexagon::SL2_loadrh_io:
    case Hexagon::SL2_loadruh_io: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 8;
      case 1:
        // op: Rs16
        return 4;
      case 0:
        // op: Rd16
        return 0;
      }
      break;
    }
    case Hexagon::C2_bitsclri:
    case Hexagon::C4_nbitsclri:
    case Hexagon::F2_sfclass:
    case Hexagon::S2_tstbit_i:
    case Hexagon::S4_ntstbit_i: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 8;
      case 1:
        // op: Rs32
        return 16;
      case 0:
        // op: Pd4
        return 0;
      }
      break;
    }
    case Hexagon::A4_cround_ri:
    case Hexagon::A4_round_ri:
    case Hexagon::A4_round_ri_sat:
    case Hexagon::A7_clip:
    case Hexagon::S2_asl_i_r:
    case Hexagon::S2_asl_i_r_sat:
    case Hexagon::S2_asr_i_r:
    case Hexagon::S2_asr_i_r_rnd:
    case Hexagon::S2_clrbit_i:
    case Hexagon::S2_lsr_i_r:
    case Hexagon::S2_setbit_i:
    case Hexagon::S2_togglebit_i:
    case Hexagon::S4_clbaddi:
    case Hexagon::S6_rol_i_r: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 8;
      case 1:
        // op: Rs32
        return 16;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::A4_bitspliti: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 8;
      case 1:
        // op: Rs32
        return 16;
      case 0:
        // op: Rdd32
        return 0;
      }
      break;
    }
    case Hexagon::S2_asr_i_svw_trun:
    case Hexagon::S4_clbpaddi:
    case Hexagon::S5_asrhub_rnd_sat:
    case Hexagon::S5_asrhub_sat: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 8;
      case 1:
        // op: Rss32
        return 16;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::A7_croundd_ri:
    case Hexagon::A7_vclip:
    case Hexagon::S2_asl_i_p:
    case Hexagon::S2_asl_i_vh:
    case Hexagon::S2_asl_i_vw:
    case Hexagon::S2_asr_i_p:
    case Hexagon::S2_asr_i_p_rnd:
    case Hexagon::S2_asr_i_vh:
    case Hexagon::S2_asr_i_vw:
    case Hexagon::S2_lsr_i_p:
    case Hexagon::S2_lsr_i_vh:
    case Hexagon::S2_lsr_i_vw:
    case Hexagon::S5_vasrhrnd:
    case Hexagon::S6_rol_i_p: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 8;
      case 1:
        // op: Rss32
        return 16;
      case 0:
        // op: Rdd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vL32Ub_ai:
    case Hexagon::V6_vL32b_ai:
    case Hexagon::V6_vL32b_cur_ai:
    case Hexagon::V6_vL32b_nt_ai:
    case Hexagon::V6_vL32b_nt_cur_ai:
    case Hexagon::V6_vL32b_nt_tmp_ai:
    case Hexagon::V6_vL32b_tmp_ai: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 8;
      case 1:
        // op: Rt32
        return 16;
      case 0:
        // op: Vd32
        return 0;
      }
      break;
    }
    case Hexagon::S2_extractu:
    case Hexagon::S4_extract: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 8;
      case 3:
        // op: II
        return 5;
      case 1:
        // op: Rs32
        return 16;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::S2_extractup:
    case Hexagon::S4_extractp: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 8;
      case 3:
        // op: II
        return 5;
      case 1:
        // op: Rss32
        return 16;
      case 0:
        // op: Rdd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vS32b_new_pi:
    case Hexagon::V6_vS32b_nt_new_pi: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 8;
      case 3:
        // op: Os8
        return 0;
      case 0:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::V6_vS32Ub_pi:
    case Hexagon::V6_vS32b_nt_pi:
    case Hexagon::V6_vS32b_pi: {
      switch (OpNum) {
      case 2:
        // op: Ii
        return 8;
      case 3:
        // op: Vs32
        return 0;
      case 0:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::V6_vS32b_srls_ppu:
    case Hexagon::V6_zLd_ppu: {
      switch (OpNum) {
      case 2:
        // op: Mu2
        return 13;
      case 0:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::S2_storerbnew_pbr:
    case Hexagon::S2_storerbnew_pcr:
    case Hexagon::S2_storerbnew_pr:
    case Hexagon::S2_storerhnew_pbr:
    case Hexagon::S2_storerhnew_pcr:
    case Hexagon::S2_storerhnew_pr:
    case Hexagon::S2_storerinew_pbr:
    case Hexagon::S2_storerinew_pcr:
    case Hexagon::S2_storerinew_pr: {
      switch (OpNum) {
      case 2:
        // op: Mu2
        return 13;
      case 3:
        // op: Nt8
        return 8;
      case 0:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::V6_vS32b_new_ppu:
    case Hexagon::V6_vS32b_nt_new_ppu: {
      switch (OpNum) {
      case 2:
        // op: Mu2
        return 13;
      case 3:
        // op: Os8
        return 0;
      case 0:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::S2_storerb_pbr:
    case Hexagon::S2_storerb_pcr:
    case Hexagon::S2_storerb_pr:
    case Hexagon::S2_storerf_pbr:
    case Hexagon::S2_storerf_pcr:
    case Hexagon::S2_storerf_pr:
    case Hexagon::S2_storerh_pbr:
    case Hexagon::S2_storerh_pcr:
    case Hexagon::S2_storerh_pr:
    case Hexagon::S2_storeri_pbr:
    case Hexagon::S2_storeri_pcr:
    case Hexagon::S2_storeri_pr: {
      switch (OpNum) {
      case 2:
        // op: Mu2
        return 13;
      case 3:
        // op: Rt32
        return 8;
      case 0:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::S2_storerd_pbr:
    case Hexagon::S2_storerd_pcr:
    case Hexagon::S2_storerd_pr: {
      switch (OpNum) {
      case 2:
        // op: Mu2
        return 13;
      case 3:
        // op: Rtt32
        return 8;
      case 0:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::V6_vS32Ub_ppu:
    case Hexagon::V6_vS32b_nt_ppu:
    case Hexagon::V6_vS32b_ppu: {
      switch (OpNum) {
      case 2:
        // op: Mu2
        return 13;
      case 3:
        // op: Vs32
        return 0;
      case 0:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::V6_vL32b_cur_npred_ppu:
    case Hexagon::V6_vL32b_cur_pred_ppu:
    case Hexagon::V6_vL32b_npred_ppu:
    case Hexagon::V6_vL32b_nt_cur_npred_ppu:
    case Hexagon::V6_vL32b_nt_cur_pred_ppu:
    case Hexagon::V6_vL32b_nt_npred_ppu:
    case Hexagon::V6_vL32b_nt_pred_ppu:
    case Hexagon::V6_vL32b_nt_tmp_npred_ppu:
    case Hexagon::V6_vL32b_nt_tmp_pred_ppu:
    case Hexagon::V6_vL32b_pred_ppu:
    case Hexagon::V6_vL32b_tmp_npred_ppu:
    case Hexagon::V6_vL32b_tmp_pred_ppu: {
      switch (OpNum) {
      case 2:
        // op: Pv4
        return 11;
      case 4:
        // op: Mu2
        return 13;
      case 0:
        // op: Vd32
        return 0;
      case 1:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::V6_vandnqrt_acc:
    case Hexagon::V6_vandqrt_acc: {
      switch (OpNum) {
      case 2:
        // op: Qu4
        return 8;
      case 3:
        // op: Rt32
        return 16;
      case 0:
        // op: Vx32
        return 0;
      }
      break;
    }
    case Hexagon::SA1_addrx: {
      switch (OpNum) {
      case 2:
        // op: Rs16
        return 4;
      case 0:
        // op: Rx16
        return 0;
      }
      break;
    }
    case Hexagon::F2_sfinvsqrta: {
      switch (OpNum) {
      case 2:
        // op: Rs32
        return 16;
      case 0:
        // op: Rd32
        return 0;
      case 1:
        // op: Pe4
        return 5;
      }
      break;
    }
    case Hexagon::F2_sfrecipa: {
      switch (OpNum) {
      case 2:
        // op: Rs32
        return 16;
      case 3:
        // op: Rt32
        return 8;
      case 0:
        // op: Rd32
        return 0;
      case 1:
        // op: Pe4
        return 5;
      }
      break;
    }
    case Hexagon::F2_sffma:
    case Hexagon::F2_sffma_lib:
    case Hexagon::F2_sffms:
    case Hexagon::F2_sffms_lib:
    case Hexagon::M2_acci:
    case Hexagon::M2_maci:
    case Hexagon::M2_mnaci:
    case Hexagon::M2_mpy_acc_hh_s0:
    case Hexagon::M2_mpy_acc_hh_s1:
    case Hexagon::M2_mpy_acc_hl_s0:
    case Hexagon::M2_mpy_acc_hl_s1:
    case Hexagon::M2_mpy_acc_lh_s0:
    case Hexagon::M2_mpy_acc_lh_s1:
    case Hexagon::M2_mpy_acc_ll_s0:
    case Hexagon::M2_mpy_acc_ll_s1:
    case Hexagon::M2_mpy_acc_sat_hh_s0:
    case Hexagon::M2_mpy_acc_sat_hh_s1:
    case Hexagon::M2_mpy_acc_sat_hl_s0:
    case Hexagon::M2_mpy_acc_sat_hl_s1:
    case Hexagon::M2_mpy_acc_sat_lh_s0:
    case Hexagon::M2_mpy_acc_sat_lh_s1:
    case Hexagon::M2_mpy_acc_sat_ll_s0:
    case Hexagon::M2_mpy_acc_sat_ll_s1:
    case Hexagon::M2_mpy_nac_hh_s0:
    case Hexagon::M2_mpy_nac_hh_s1:
    case Hexagon::M2_mpy_nac_hl_s0:
    case Hexagon::M2_mpy_nac_hl_s1:
    case Hexagon::M2_mpy_nac_lh_s0:
    case Hexagon::M2_mpy_nac_lh_s1:
    case Hexagon::M2_mpy_nac_ll_s0:
    case Hexagon::M2_mpy_nac_ll_s1:
    case Hexagon::M2_mpy_nac_sat_hh_s0:
    case Hexagon::M2_mpy_nac_sat_hh_s1:
    case Hexagon::M2_mpy_nac_sat_hl_s0:
    case Hexagon::M2_mpy_nac_sat_hl_s1:
    case Hexagon::M2_mpy_nac_sat_lh_s0:
    case Hexagon::M2_mpy_nac_sat_lh_s1:
    case Hexagon::M2_mpy_nac_sat_ll_s0:
    case Hexagon::M2_mpy_nac_sat_ll_s1:
    case Hexagon::M2_mpyu_acc_hh_s0:
    case Hexagon::M2_mpyu_acc_hh_s1:
    case Hexagon::M2_mpyu_acc_hl_s0:
    case Hexagon::M2_mpyu_acc_hl_s1:
    case Hexagon::M2_mpyu_acc_lh_s0:
    case Hexagon::M2_mpyu_acc_lh_s1:
    case Hexagon::M2_mpyu_acc_ll_s0:
    case Hexagon::M2_mpyu_acc_ll_s1:
    case Hexagon::M2_mpyu_nac_hh_s0:
    case Hexagon::M2_mpyu_nac_hh_s1:
    case Hexagon::M2_mpyu_nac_hl_s0:
    case Hexagon::M2_mpyu_nac_hl_s1:
    case Hexagon::M2_mpyu_nac_lh_s0:
    case Hexagon::M2_mpyu_nac_lh_s1:
    case Hexagon::M2_mpyu_nac_ll_s0:
    case Hexagon::M2_mpyu_nac_ll_s1:
    case Hexagon::M2_nacci:
    case Hexagon::M2_xor_xacc:
    case Hexagon::M4_and_and:
    case Hexagon::M4_and_andn:
    case Hexagon::M4_and_or:
    case Hexagon::M4_and_xor:
    case Hexagon::M4_mac_up_s1_sat:
    case Hexagon::M4_nac_up_s1_sat:
    case Hexagon::M4_or_and:
    case Hexagon::M4_or_andn:
    case Hexagon::M4_or_or:
    case Hexagon::M4_or_xor:
    case Hexagon::M4_xor_and:
    case Hexagon::M4_xor_andn:
    case Hexagon::M4_xor_or:
    case Hexagon::S2_asl_r_r_acc:
    case Hexagon::S2_asl_r_r_and:
    case Hexagon::S2_asl_r_r_nac:
    case Hexagon::S2_asl_r_r_or:
    case Hexagon::S2_asr_r_r_acc:
    case Hexagon::S2_asr_r_r_and:
    case Hexagon::S2_asr_r_r_nac:
    case Hexagon::S2_asr_r_r_or:
    case Hexagon::S2_lsl_r_r_acc:
    case Hexagon::S2_lsl_r_r_and:
    case Hexagon::S2_lsl_r_r_nac:
    case Hexagon::S2_lsl_r_r_or:
    case Hexagon::S2_lsr_r_r_acc:
    case Hexagon::S2_lsr_r_r_and:
    case Hexagon::S2_lsr_r_r_nac:
    case Hexagon::S2_lsr_r_r_or: {
      switch (OpNum) {
      case 2:
        // op: Rs32
        return 16;
      case 3:
        // op: Rt32
        return 8;
      case 0:
        // op: Rx32
        return 0;
      }
      break;
    }
    case Hexagon::M2_cmaci_s0:
    case Hexagon::M2_cmacr_s0:
    case Hexagon::M2_cmacs_s0:
    case Hexagon::M2_cmacs_s1:
    case Hexagon::M2_cmacsc_s0:
    case Hexagon::M2_cmacsc_s1:
    case Hexagon::M2_cnacs_s0:
    case Hexagon::M2_cnacs_s1:
    case Hexagon::M2_cnacsc_s0:
    case Hexagon::M2_cnacsc_s1:
    case Hexagon::M2_dpmpyss_acc_s0:
    case Hexagon::M2_dpmpyss_nac_s0:
    case Hexagon::M2_dpmpyuu_acc_s0:
    case Hexagon::M2_dpmpyuu_nac_s0:
    case Hexagon::M2_mpyd_acc_hh_s0:
    case Hexagon::M2_mpyd_acc_hh_s1:
    case Hexagon::M2_mpyd_acc_hl_s0:
    case Hexagon::M2_mpyd_acc_hl_s1:
    case Hexagon::M2_mpyd_acc_lh_s0:
    case Hexagon::M2_mpyd_acc_lh_s1:
    case Hexagon::M2_mpyd_acc_ll_s0:
    case Hexagon::M2_mpyd_acc_ll_s1:
    case Hexagon::M2_mpyd_nac_hh_s0:
    case Hexagon::M2_mpyd_nac_hh_s1:
    case Hexagon::M2_mpyd_nac_hl_s0:
    case Hexagon::M2_mpyd_nac_hl_s1:
    case Hexagon::M2_mpyd_nac_lh_s0:
    case Hexagon::M2_mpyd_nac_lh_s1:
    case Hexagon::M2_mpyd_nac_ll_s0:
    case Hexagon::M2_mpyd_nac_ll_s1:
    case Hexagon::M2_mpyud_acc_hh_s0:
    case Hexagon::M2_mpyud_acc_hh_s1:
    case Hexagon::M2_mpyud_acc_hl_s0:
    case Hexagon::M2_mpyud_acc_hl_s1:
    case Hexagon::M2_mpyud_acc_lh_s0:
    case Hexagon::M2_mpyud_acc_lh_s1:
    case Hexagon::M2_mpyud_acc_ll_s0:
    case Hexagon::M2_mpyud_acc_ll_s1:
    case Hexagon::M2_mpyud_nac_hh_s0:
    case Hexagon::M2_mpyud_nac_hh_s1:
    case Hexagon::M2_mpyud_nac_hl_s0:
    case Hexagon::M2_mpyud_nac_hl_s1:
    case Hexagon::M2_mpyud_nac_lh_s0:
    case Hexagon::M2_mpyud_nac_lh_s1:
    case Hexagon::M2_mpyud_nac_ll_s0:
    case Hexagon::M2_mpyud_nac_ll_s1:
    case Hexagon::M2_vmac2:
    case Hexagon::M2_vmac2s_s0:
    case Hexagon::M2_vmac2s_s1:
    case Hexagon::M2_vmac2su_s0:
    case Hexagon::M2_vmac2su_s1:
    case Hexagon::M4_pmpyw_acc:
    case Hexagon::M4_vpmpyh_acc:
    case Hexagon::M5_vmacbsu:
    case Hexagon::M5_vmacbuu: {
      switch (OpNum) {
      case 2:
        // op: Rs32
        return 16;
      case 3:
        // op: Rt32
        return 8;
      case 0:
        // op: Rxx32
        return 0;
      }
      break;
    }
    case Hexagon::F2_sffma_sc: {
      switch (OpNum) {
      case 2:
        // op: Rs32
        return 16;
      case 3:
        // op: Rt32
        return 8;
      case 4:
        // op: Pu4
        return 5;
      case 0:
        // op: Rx32
        return 0;
      }
      break;
    }
    case Hexagon::S2_insert_rp: {
      switch (OpNum) {
      case 2:
        // op: Rs32
        return 16;
      case 3:
        // op: Rtt32
        return 8;
      case 0:
        // op: Rx32
        return 0;
      }
      break;
    }
    case Hexagon::S2_asl_r_p_acc:
    case Hexagon::S2_asl_r_p_and:
    case Hexagon::S2_asl_r_p_nac:
    case Hexagon::S2_asl_r_p_or:
    case Hexagon::S2_asl_r_p_xor:
    case Hexagon::S2_asr_r_p_acc:
    case Hexagon::S2_asr_r_p_and:
    case Hexagon::S2_asr_r_p_nac:
    case Hexagon::S2_asr_r_p_or:
    case Hexagon::S2_asr_r_p_xor:
    case Hexagon::S2_lsl_r_p_acc:
    case Hexagon::S2_lsl_r_p_and:
    case Hexagon::S2_lsl_r_p_nac:
    case Hexagon::S2_lsl_r_p_or:
    case Hexagon::S2_lsl_r_p_xor:
    case Hexagon::S2_lsr_r_p_acc:
    case Hexagon::S2_lsr_r_p_and:
    case Hexagon::S2_lsr_r_p_nac:
    case Hexagon::S2_lsr_r_p_or:
    case Hexagon::S2_lsr_r_p_xor:
    case Hexagon::S2_vrcnegh: {
      switch (OpNum) {
      case 2:
        // op: Rss32
        return 16;
      case 3:
        // op: Rt32
        return 8;
      case 0:
        // op: Rxx32
        return 0;
      }
      break;
    }
    case Hexagon::A4_addp_c:
    case Hexagon::A4_subp_c: {
      switch (OpNum) {
      case 2:
        // op: Rss32
        return 16;
      case 3:
        // op: Rtt32
        return 8;
      case 0:
        // op: Rdd32
        return 0;
      case 1:
        // op: Px4
        return 5;
      }
      break;
    }
    case Hexagon::A2_vraddub_acc:
    case Hexagon::A2_vrsadub_acc:
    case Hexagon::F2_dfmpyhh:
    case Hexagon::F2_dfmpylh:
    case Hexagon::M2_mmachs_rs0:
    case Hexagon::M2_mmachs_rs1:
    case Hexagon::M2_mmachs_s0:
    case Hexagon::M2_mmachs_s1:
    case Hexagon::M2_mmacls_rs0:
    case Hexagon::M2_mmacls_rs1:
    case Hexagon::M2_mmacls_s0:
    case Hexagon::M2_mmacls_s1:
    case Hexagon::M2_mmacuhs_rs0:
    case Hexagon::M2_mmacuhs_rs1:
    case Hexagon::M2_mmacuhs_s0:
    case Hexagon::M2_mmacuhs_s1:
    case Hexagon::M2_mmaculs_rs0:
    case Hexagon::M2_mmaculs_rs1:
    case Hexagon::M2_mmaculs_s0:
    case Hexagon::M2_mmaculs_s1:
    case Hexagon::M2_vcmac_s0_sat_i:
    case Hexagon::M2_vcmac_s0_sat_r:
    case Hexagon::M2_vdmacs_s0:
    case Hexagon::M2_vdmacs_s1:
    case Hexagon::M2_vmac2es:
    case Hexagon::M2_vmac2es_s0:
    case Hexagon::M2_vmac2es_s1:
    case Hexagon::M2_vrcmaci_s0:
    case Hexagon::M2_vrcmaci_s0c:
    case Hexagon::M2_vrcmacr_s0:
    case Hexagon::M2_vrcmacr_s0c:
    case Hexagon::M2_vrcmpys_acc_s1_h:
    case Hexagon::M2_vrcmpys_acc_s1_l:
    case Hexagon::M2_vrmac_s0:
    case Hexagon::M4_vrmpyeh_acc_s0:
    case Hexagon::M4_vrmpyeh_acc_s1:
    case Hexagon::M4_vrmpyoh_acc_s0:
    case Hexagon::M4_vrmpyoh_acc_s1:
    case Hexagon::M4_xor_xacc:
    case Hexagon::M5_vdmacbsu:
    case Hexagon::M5_vrmacbsu:
    case Hexagon::M5_vrmacbuu:
    case Hexagon::M7_dcmpyiw_acc:
    case Hexagon::M7_dcmpyiwc_acc:
    case Hexagon::M7_dcmpyrw_acc:
    case Hexagon::M7_dcmpyrwc_acc:
    case Hexagon::S2_insertp_rp: {
      switch (OpNum) {
      case 2:
        // op: Rss32
        return 16;
      case 3:
        // op: Rtt32
        return 8;
      case 0:
        // op: Rxx32
        return 0;
      }
      break;
    }
    case Hexagon::A4_vrmaxh:
    case Hexagon::A4_vrmaxuh:
    case Hexagon::A4_vrmaxuw:
    case Hexagon::A4_vrmaxw:
    case Hexagon::A4_vrminh:
    case Hexagon::A4_vrminuh:
    case Hexagon::A4_vrminuw:
    case Hexagon::A4_vrminw: {
      switch (OpNum) {
      case 2:
        // op: Rss32
        return 16;
      case 3:
        // op: Ru32
        return 0;
      case 0:
        // op: Rxx32
        return 8;
      }
      break;
    }
    case Hexagon::V6_vinsertwr: {
      switch (OpNum) {
      case 2:
        // op: Rt32
        return 16;
      case 0:
        // op: Vx32
        return 0;
      }
      break;
    }
    case Hexagon::M2_subacc: {
      switch (OpNum) {
      case 2:
        // op: Rt32
        return 8;
      case 3:
        // op: Rs32
        return 16;
      case 0:
        // op: Rx32
        return 0;
      }
      break;
    }
    case Hexagon::A6_vminub_RdP: {
      switch (OpNum) {
      case 2:
        // op: Rtt32
        return 8;
      case 3:
        // op: Rss32
        return 16;
      case 0:
        // op: Rdd32
        return 0;
      case 1:
        // op: Pe4
        return 5;
      }
      break;
    }
    case Hexagon::V6_vrmpyzbb_rx:
    case Hexagon::V6_vrmpyzbub_rx:
    case Hexagon::V6_vrmpyzcb_rx:
    case Hexagon::V6_vrmpyzcbs_rx:
    case Hexagon::V6_vrmpyznb_rx: {
      switch (OpNum) {
      case 2:
        // op: Vu32
        return 8;
      case 0:
        // op: Vdddd32
        return 0;
      case 1:
        // op: Rx8
        return 16;
      }
      break;
    }
    case Hexagon::V6_vunpackob:
    case Hexagon::V6_vunpackoh: {
      switch (OpNum) {
      case 2:
        // op: Vu32
        return 8;
      case 0:
        // op: Vxx32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vandvrt_acc: {
      switch (OpNum) {
      case 2:
        // op: Vu32
        return 8;
      case 3:
        // op: Rt32
        return 16;
      case 0:
        // op: Qx4
        return 0;
      }
      break;
    }
    case Hexagon::V6_get_qfext_oracc:
    case Hexagon::V6_vaslh_acc:
    case Hexagon::V6_vaslw_acc:
    case Hexagon::V6_vasrh_acc:
    case Hexagon::V6_vasrw_acc:
    case Hexagon::V6_vdmpybus_acc:
    case Hexagon::V6_vdmpyhb_acc:
    case Hexagon::V6_vdmpyhsat_acc:
    case Hexagon::V6_vdmpyhsusat_acc:
    case Hexagon::V6_vmpyihb_acc:
    case Hexagon::V6_vmpyiwb_acc:
    case Hexagon::V6_vmpyiwh_acc:
    case Hexagon::V6_vmpyiwub_acc:
    case Hexagon::V6_vmpyuhe_acc:
    case Hexagon::V6_vrmpybus_acc:
    case Hexagon::V6_vrmpyub_acc: {
      switch (OpNum) {
      case 2:
        // op: Vu32
        return 8;
      case 3:
        // op: Rt32
        return 16;
      case 0:
        // op: Vx32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vmpybus_acc:
    case Hexagon::V6_vmpyh_acc:
    case Hexagon::V6_vmpyhsat_acc:
    case Hexagon::V6_vmpyub_acc:
    case Hexagon::V6_vmpyuh_acc: {
      switch (OpNum) {
      case 2:
        // op: Vu32
        return 8;
      case 3:
        // op: Rt32
        return 16;
      case 0:
        // op: Vxx32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vrmpyzbb_rt_acc:
    case Hexagon::V6_vrmpyzbub_rt_acc:
    case Hexagon::V6_vrmpyzcb_rt_acc:
    case Hexagon::V6_vrmpyzcbs_rt_acc:
    case Hexagon::V6_vrmpyznb_rt_acc: {
      switch (OpNum) {
      case 2:
        // op: Vu32
        return 8;
      case 3:
        // op: Rt8
        return 16;
      case 0:
        // op: Vyyyy32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vmpahhsat:
    case Hexagon::V6_vmpauhuhsat:
    case Hexagon::V6_vmpsuhuhsat: {
      switch (OpNum) {
      case 2:
        // op: Vu32
        return 8;
      case 3:
        // op: Rtt32
        return 16;
      case 0:
        // op: Vx32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vrmpybub_rtt_acc:
    case Hexagon::V6_vrmpyub_rtt_acc: {
      switch (OpNum) {
      case 2:
        // op: Vu32
        return 8;
      case 3:
        // op: Rtt32
        return 16;
      case 0:
        // op: Vxx32
        return 0;
      }
      break;
    }
    case Hexagon::V6_veqb_and:
    case Hexagon::V6_veqb_or:
    case Hexagon::V6_veqb_xor:
    case Hexagon::V6_veqh_and:
    case Hexagon::V6_veqh_or:
    case Hexagon::V6_veqh_xor:
    case Hexagon::V6_veqhf_and:
    case Hexagon::V6_veqhf_or:
    case Hexagon::V6_veqhf_xor:
    case Hexagon::V6_veqsf_and:
    case Hexagon::V6_veqsf_or:
    case Hexagon::V6_veqsf_xor:
    case Hexagon::V6_veqw_and:
    case Hexagon::V6_veqw_or:
    case Hexagon::V6_veqw_xor:
    case Hexagon::V6_vgtb_and:
    case Hexagon::V6_vgtb_or:
    case Hexagon::V6_vgtb_xor:
    case Hexagon::V6_vgtbf_and:
    case Hexagon::V6_vgtbf_or:
    case Hexagon::V6_vgtbf_xor:
    case Hexagon::V6_vgth_and:
    case Hexagon::V6_vgth_or:
    case Hexagon::V6_vgth_xor:
    case Hexagon::V6_vgthf_and:
    case Hexagon::V6_vgthf_or:
    case Hexagon::V6_vgthf_xor:
    case Hexagon::V6_vgtsf_and:
    case Hexagon::V6_vgtsf_or:
    case Hexagon::V6_vgtsf_xor:
    case Hexagon::V6_vgtub_and:
    case Hexagon::V6_vgtub_or:
    case Hexagon::V6_vgtub_xor:
    case Hexagon::V6_vgtuh_and:
    case Hexagon::V6_vgtuh_or:
    case Hexagon::V6_vgtuh_xor:
    case Hexagon::V6_vgtuw_and:
    case Hexagon::V6_vgtuw_or:
    case Hexagon::V6_vgtuw_xor:
    case Hexagon::V6_vgtw_and:
    case Hexagon::V6_vgtw_or:
    case Hexagon::V6_vgtw_xor: {
      switch (OpNum) {
      case 2:
        // op: Vu32
        return 8;
      case 3:
        // op: Vv32
        return 16;
      case 0:
        // op: Qx4
        return 0;
      }
      break;
    }
    case Hexagon::V6_vaddcarryo:
    case Hexagon::V6_vsubcarryo: {
      switch (OpNum) {
      case 2:
        // op: Vu32
        return 8;
      case 3:
        // op: Vv32
        return 16;
      case 0:
        // op: Vd32
        return 0;
      case 1:
        // op: Qe4
        return 5;
      }
      break;
    }
    case Hexagon::V6_vaddcarry:
    case Hexagon::V6_vsubcarry: {
      switch (OpNum) {
      case 2:
        // op: Vu32
        return 8;
      case 3:
        // op: Vv32
        return 16;
      case 0:
        // op: Vd32
        return 0;
      case 1:
        // op: Qx4
        return 5;
      }
      break;
    }
    case Hexagon::V6_vdmpy_sf_hf_acc:
    case Hexagon::V6_vdmpyhvsat_acc:
    case Hexagon::V6_vmpy_hf_hf_acc:
    case Hexagon::V6_vmpyiewh_acc:
    case Hexagon::V6_vmpyiewuh_acc:
    case Hexagon::V6_vmpyih_acc:
    case Hexagon::V6_vmpyowh_rnd_sacc:
    case Hexagon::V6_vmpyowh_sacc:
    case Hexagon::V6_vrmpybusv_acc:
    case Hexagon::V6_vrmpybv_acc:
    case Hexagon::V6_vrmpyubv_acc: {
      switch (OpNum) {
      case 2:
        // op: Vu32
        return 8;
      case 3:
        // op: Vv32
        return 16;
      case 0:
        // op: Vx32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vaddhw_acc:
    case Hexagon::V6_vaddubh_acc:
    case Hexagon::V6_vadduhw_acc:
    case Hexagon::V6_vasr_into:
    case Hexagon::V6_vmpy_hf_f8_acc:
    case Hexagon::V6_vmpy_sf_bf_acc:
    case Hexagon::V6_vmpy_sf_hf_acc:
    case Hexagon::V6_vmpybusv_acc:
    case Hexagon::V6_vmpybv_acc:
    case Hexagon::V6_vmpyhus_acc:
    case Hexagon::V6_vmpyhv_acc:
    case Hexagon::V6_vmpyowh_64_acc:
    case Hexagon::V6_vmpyubv_acc:
    case Hexagon::V6_vmpyuhv_acc: {
      switch (OpNum) {
      case 2:
        // op: Vu32
        return 8;
      case 3:
        // op: Vv32
        return 16;
      case 0:
        // op: Vxx32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vlutvvb_oracc: {
      switch (OpNum) {
      case 2:
        // op: Vu32
        return 8;
      case 3:
        // op: Vv32
        return 19;
      case 4:
        // op: Rt8
        return 16;
      case 0:
        // op: Vx32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vlutvwh_oracc: {
      switch (OpNum) {
      case 2:
        // op: Vu32
        return 8;
      case 3:
        // op: Vv32
        return 19;
      case 4:
        // op: Rt8
        return 16;
      case 0:
        // op: Vxx32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vdmpyhisat_acc:
    case Hexagon::V6_vdmpyhsuisat_acc: {
      switch (OpNum) {
      case 2:
        // op: Vuu32
        return 8;
      case 3:
        // op: Rt32
        return 16;
      case 0:
        // op: Vx32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vdmpybus_dv_acc:
    case Hexagon::V6_vdmpyhb_dv_acc:
    case Hexagon::V6_vdsaduh_acc:
    case Hexagon::V6_vmpabus_acc:
    case Hexagon::V6_vmpabuu_acc:
    case Hexagon::V6_vmpahb_acc:
    case Hexagon::V6_vmpauhb_acc:
    case Hexagon::V6_vtmpyb_acc:
    case Hexagon::V6_vtmpybus_acc:
    case Hexagon::V6_vtmpyhb_acc: {
      switch (OpNum) {
      case 2:
        // op: Vuu32
        return 8;
      case 3:
        // op: Rt32
        return 16;
      case 0:
        // op: Vxx32
        return 0;
      }
      break;
    }
    case Hexagon::L4_loadalignb_ap:
    case Hexagon::L4_loadalignh_ap: {
      switch (OpNum) {
      case 3:
        // op: II
        return 5;
      case 0:
        // op: Ryy32
        return 0;
      case 1:
        // op: Re32
        return 16;
      }
      break;
    }
    case Hexagon::S2_pstorerbnewf_pi:
    case Hexagon::S2_pstorerbnewfnew_pi:
    case Hexagon::S2_pstorerbnewt_pi:
    case Hexagon::S2_pstorerbnewtnew_pi:
    case Hexagon::S2_pstorerhnewf_pi:
    case Hexagon::S2_pstorerhnewfnew_pi:
    case Hexagon::S2_pstorerhnewt_pi:
    case Hexagon::S2_pstorerhnewtnew_pi:
    case Hexagon::S2_pstorerinewf_pi:
    case Hexagon::S2_pstorerinewfnew_pi:
    case Hexagon::S2_pstorerinewt_pi:
    case Hexagon::S2_pstorerinewtnew_pi: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 3;
      case 1:
        // op: Pv4
        return 0;
      case 4:
        // op: Nt8
        return 8;
      case 0:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::S2_pstorerbf_pi:
    case Hexagon::S2_pstorerbfnew_pi:
    case Hexagon::S2_pstorerbt_pi:
    case Hexagon::S2_pstorerbtnew_pi:
    case Hexagon::S2_pstorerff_pi:
    case Hexagon::S2_pstorerffnew_pi:
    case Hexagon::S2_pstorerft_pi:
    case Hexagon::S2_pstorerftnew_pi:
    case Hexagon::S2_pstorerhf_pi:
    case Hexagon::S2_pstorerhfnew_pi:
    case Hexagon::S2_pstorerht_pi:
    case Hexagon::S2_pstorerhtnew_pi:
    case Hexagon::S2_pstorerif_pi:
    case Hexagon::S2_pstorerifnew_pi:
    case Hexagon::S2_pstorerit_pi:
    case Hexagon::S2_pstoreritnew_pi: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 3;
      case 1:
        // op: Pv4
        return 0;
      case 4:
        // op: Rt32
        return 8;
      case 0:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::S2_pstorerdf_pi:
    case Hexagon::S2_pstorerdfnew_pi:
    case Hexagon::S2_pstorerdt_pi:
    case Hexagon::S2_pstorerdtnew_pi: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 3;
      case 1:
        // op: Pv4
        return 0;
      case 4:
        // op: Rtt32
        return 8;
      case 0:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::L2_loadbsw2_pi:
    case Hexagon::L2_loadbzw2_pi:
    case Hexagon::L2_loadrb_pi:
    case Hexagon::L2_loadrh_pi:
    case Hexagon::L2_loadri_pi:
    case Hexagon::L2_loadrub_pi:
    case Hexagon::L2_loadruh_pi: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 5;
      case 0:
        // op: Rd32
        return 0;
      case 1:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::L2_loadbsw4_pi:
    case Hexagon::L2_loadbzw4_pi:
    case Hexagon::L2_loadrd_pi: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 5;
      case 0:
        // op: Rdd32
        return 0;
      case 1:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::L2_ploadrbf_io:
    case Hexagon::L2_ploadrbfnew_io:
    case Hexagon::L2_ploadrbt_io:
    case Hexagon::L2_ploadrbtnew_io:
    case Hexagon::L2_ploadrhf_io:
    case Hexagon::L2_ploadrhfnew_io:
    case Hexagon::L2_ploadrht_io:
    case Hexagon::L2_ploadrhtnew_io:
    case Hexagon::L2_ploadrif_io:
    case Hexagon::L2_ploadrifnew_io:
    case Hexagon::L2_ploadrit_io:
    case Hexagon::L2_ploadritnew_io:
    case Hexagon::L2_ploadrubf_io:
    case Hexagon::L2_ploadrubfnew_io:
    case Hexagon::L2_ploadrubt_io:
    case Hexagon::L2_ploadrubtnew_io:
    case Hexagon::L2_ploadruhf_io:
    case Hexagon::L2_ploadruhfnew_io:
    case Hexagon::L2_ploadruht_io:
    case Hexagon::L2_ploadruhtnew_io: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 5;
      case 1:
        // op: Pt4
        return 11;
      case 2:
        // op: Rs32
        return 16;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::L2_ploadrdf_io:
    case Hexagon::L2_ploadrdfnew_io:
    case Hexagon::L2_ploadrdt_io:
    case Hexagon::L2_ploadrdtnew_io: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 5;
      case 1:
        // op: Pt4
        return 11;
      case 2:
        // op: Rs32
        return 16;
      case 0:
        // op: Rdd32
        return 0;
      }
      break;
    }
    case Hexagon::A2_paddif:
    case Hexagon::A2_paddifnew:
    case Hexagon::A2_paddit:
    case Hexagon::A2_padditnew:
    case Hexagon::C2_muxir: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 5;
      case 1:
        // op: Pu4
        return 21;
      case 2:
        // op: Rs32
        return 16;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::S4_addaddi: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 5;
      case 1:
        // op: Rs32
        return 16;
      case 2:
        // op: Ru32
        return 0;
      case 0:
        // op: Rd32
        return 8;
      }
      break;
    }
    case Hexagon::S4_vrcrotate: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 5;
      case 1:
        // op: Rss32
        return 16;
      case 2:
        // op: Rt32
        return 8;
      case 0:
        // op: Rdd32
        return 0;
      }
      break;
    }
    case Hexagon::S2_vspliceib: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 5;
      case 1:
        // op: Rss32
        return 16;
      case 2:
        // op: Rtt32
        return 8;
      case 0:
        // op: Rdd32
        return 0;
      }
      break;
    }
    case Hexagon::S2_addasl_rrri: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 5;
      case 1:
        // op: Rt32
        return 8;
      case 2:
        // op: Rs32
        return 16;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::S2_valignib: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 5;
      case 1:
        // op: Rtt32
        return 8;
      case 2:
        // op: Rss32
        return 16;
      case 0:
        // op: Rdd32
        return 0;
      }
      break;
    }
    case Hexagon::S4_or_andix: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 5;
      case 1:
        // op: Ru32
        return 0;
      case 0:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::M4_mpyri_addr: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 5;
      case 1:
        // op: Ru32
        return 0;
      case 2:
        // op: Rs32
        return 16;
      case 0:
        // op: Rd32
        return 8;
      }
      break;
    }
    case Hexagon::V6_valignbi:
    case Hexagon::V6_vlalignbi:
    case Hexagon::V6_vlutvvbi: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 5;
      case 1:
        // op: Vu32
        return 8;
      case 2:
        // op: Vv32
        return 16;
      case 0:
        // op: Vd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vlutvwhi: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 5;
      case 1:
        // op: Vu32
        return 8;
      case 2:
        // op: Vv32
        return 16;
      case 0:
        // op: Vdd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vrmpybusi:
    case Hexagon::V6_vrmpyubi:
    case Hexagon::V6_vrsadubi: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 5;
      case 1:
        // op: Vuu32
        return 8;
      case 2:
        // op: Rt32
        return 16;
      case 0:
        // op: Vdd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_v6mpyhubs10:
    case Hexagon::V6_v6mpyvubs10: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 5;
      case 1:
        // op: Vuu32
        return 8;
      case 2:
        // op: Vvv32
        return 16;
      case 0:
        // op: Vdd32
        return 0;
      }
      break;
    }
    case Hexagon::M2_accii:
    case Hexagon::M2_macsin:
    case Hexagon::M2_macsip:
    case Hexagon::M2_naccii:
    case Hexagon::S4_or_andi:
    case Hexagon::S4_or_ori: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 5;
      case 2:
        // op: Rs32
        return 16;
      case 0:
        // op: Rx32
        return 0;
      }
      break;
    }
    case Hexagon::L2_loadalignb_io:
    case Hexagon::L2_loadalignh_io: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 5;
      case 2:
        // op: Rs32
        return 16;
      case 0:
        // op: Ryy32
        return 0;
      }
      break;
    }
    case Hexagon::S2_tableidxb:
    case Hexagon::S2_tableidxd:
    case Hexagon::S2_tableidxh:
    case Hexagon::S2_tableidxw: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 5;
      case 4:
        // op: II
        return 8;
      case 2:
        // op: Rs32
        return 16;
      case 0:
        // op: Rx32
        return 0;
      }
      break;
    }
    case Hexagon::L2_loadbsw2_pci:
    case Hexagon::L2_loadbzw2_pci:
    case Hexagon::L2_loadrb_pci:
    case Hexagon::L2_loadrh_pci:
    case Hexagon::L2_loadri_pci:
    case Hexagon::L2_loadrub_pci:
    case Hexagon::L2_loadruh_pci: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 5;
      case 4:
        // op: Mu2
        return 13;
      case 0:
        // op: Rd32
        return 0;
      case 1:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::L2_loadbsw4_pci:
    case Hexagon::L2_loadbzw4_pci:
    case Hexagon::L2_loadrd_pci: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 5;
      case 4:
        // op: Mu2
        return 13;
      case 0:
        // op: Rdd32
        return 0;
      case 1:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::S4_pstorerbnewf_rr:
    case Hexagon::S4_pstorerbnewfnew_rr:
    case Hexagon::S4_pstorerbnewt_rr:
    case Hexagon::S4_pstorerbnewtnew_rr:
    case Hexagon::S4_pstorerhnewf_rr:
    case Hexagon::S4_pstorerhnewfnew_rr:
    case Hexagon::S4_pstorerhnewt_rr:
    case Hexagon::S4_pstorerhnewtnew_rr:
    case Hexagon::S4_pstorerinewf_rr:
    case Hexagon::S4_pstorerinewfnew_rr:
    case Hexagon::S4_pstorerinewt_rr:
    case Hexagon::S4_pstorerinewtnew_rr: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 7;
      case 0:
        // op: Pv4
        return 5;
      case 1:
        // op: Rs32
        return 16;
      case 2:
        // op: Ru32
        return 8;
      case 4:
        // op: Nt8
        return 0;
      }
      break;
    }
    case Hexagon::S4_pstorerbf_rr:
    case Hexagon::S4_pstorerbfnew_rr:
    case Hexagon::S4_pstorerbt_rr:
    case Hexagon::S4_pstorerbtnew_rr:
    case Hexagon::S4_pstorerff_rr:
    case Hexagon::S4_pstorerffnew_rr:
    case Hexagon::S4_pstorerft_rr:
    case Hexagon::S4_pstorerftnew_rr:
    case Hexagon::S4_pstorerhf_rr:
    case Hexagon::S4_pstorerhfnew_rr:
    case Hexagon::S4_pstorerht_rr:
    case Hexagon::S4_pstorerhtnew_rr:
    case Hexagon::S4_pstorerif_rr:
    case Hexagon::S4_pstorerifnew_rr:
    case Hexagon::S4_pstorerit_rr:
    case Hexagon::S4_pstoreritnew_rr: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 7;
      case 0:
        // op: Pv4
        return 5;
      case 1:
        // op: Rs32
        return 16;
      case 2:
        // op: Ru32
        return 8;
      case 4:
        // op: Rt32
        return 0;
      }
      break;
    }
    case Hexagon::S4_pstorerdf_rr:
    case Hexagon::S4_pstorerdfnew_rr:
    case Hexagon::S4_pstorerdt_rr:
    case Hexagon::S4_pstorerdtnew_rr: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 7;
      case 0:
        // op: Pv4
        return 5;
      case 1:
        // op: Rs32
        return 16;
      case 2:
        // op: Ru32
        return 8;
      case 4:
        // op: Rtt32
        return 0;
      }
      break;
    }
    case Hexagon::L4_loadrb_rr:
    case Hexagon::L4_loadrh_rr:
    case Hexagon::L4_loadri_rr:
    case Hexagon::L4_loadrub_rr:
    case Hexagon::L4_loadruh_rr: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 7;
      case 1:
        // op: Rs32
        return 16;
      case 2:
        // op: Rt32
        return 8;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::L4_loadrd_rr: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 7;
      case 1:
        // op: Rs32
        return 16;
      case 2:
        // op: Rt32
        return 8;
      case 0:
        // op: Rdd32
        return 0;
      }
      break;
    }
    case Hexagon::L4_loadalignb_ur:
    case Hexagon::L4_loadalignh_ur: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 7;
      case 4:
        // op: II
        return 5;
      case 2:
        // op: Rt32
        return 16;
      case 0:
        // op: Ryy32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vL32Ub_pi:
    case Hexagon::V6_vL32b_cur_pi:
    case Hexagon::V6_vL32b_nt_cur_pi:
    case Hexagon::V6_vL32b_nt_pi:
    case Hexagon::V6_vL32b_nt_tmp_pi:
    case Hexagon::V6_vL32b_pi:
    case Hexagon::V6_vL32b_tmp_pi: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 8;
      case 0:
        // op: Vd32
        return 0;
      case 1:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::V6_zLd_pred_pi: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 8;
      case 1:
        // op: Pv4
        return 11;
      case 0:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::V6_vL32b_cur_npred_ai:
    case Hexagon::V6_vL32b_cur_pred_ai:
    case Hexagon::V6_vL32b_npred_ai:
    case Hexagon::V6_vL32b_nt_cur_npred_ai:
    case Hexagon::V6_vL32b_nt_cur_pred_ai:
    case Hexagon::V6_vL32b_nt_npred_ai:
    case Hexagon::V6_vL32b_nt_pred_ai:
    case Hexagon::V6_vL32b_nt_tmp_npred_ai:
    case Hexagon::V6_vL32b_nt_tmp_pred_ai:
    case Hexagon::V6_vL32b_pred_ai:
    case Hexagon::V6_vL32b_tmp_npred_ai:
    case Hexagon::V6_vL32b_tmp_pred_ai: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 8;
      case 1:
        // op: Pv4
        return 11;
      case 2:
        // op: Rt32
        return 16;
      case 0:
        // op: Vd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vS32b_new_npred_pi:
    case Hexagon::V6_vS32b_new_pred_pi:
    case Hexagon::V6_vS32b_nt_new_npred_pi:
    case Hexagon::V6_vS32b_nt_new_pred_pi: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 8;
      case 1:
        // op: Pv4
        return 11;
      case 4:
        // op: Os8
        return 0;
      case 0:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::V6_vS32Ub_npred_pi:
    case Hexagon::V6_vS32Ub_pred_pi:
    case Hexagon::V6_vS32b_npred_pi:
    case Hexagon::V6_vS32b_nt_npred_pi:
    case Hexagon::V6_vS32b_nt_pred_pi:
    case Hexagon::V6_vS32b_pred_pi: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 8;
      case 1:
        // op: Pv4
        return 11;
      case 4:
        // op: Vs32
        return 0;
      case 0:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::V6_vS32b_nqpred_pi:
    case Hexagon::V6_vS32b_nt_nqpred_pi:
    case Hexagon::V6_vS32b_nt_qpred_pi:
    case Hexagon::V6_vS32b_qpred_pi: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 8;
      case 1:
        // op: Qv4
        return 11;
      case 4:
        // op: Vs32
        return 0;
      case 0:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::S2_asl_i_r_acc:
    case Hexagon::S2_asl_i_r_and:
    case Hexagon::S2_asl_i_r_nac:
    case Hexagon::S2_asl_i_r_or:
    case Hexagon::S2_asl_i_r_xacc:
    case Hexagon::S2_asr_i_r_acc:
    case Hexagon::S2_asr_i_r_and:
    case Hexagon::S2_asr_i_r_nac:
    case Hexagon::S2_asr_i_r_or:
    case Hexagon::S2_lsr_i_r_acc:
    case Hexagon::S2_lsr_i_r_and:
    case Hexagon::S2_lsr_i_r_nac:
    case Hexagon::S2_lsr_i_r_or:
    case Hexagon::S2_lsr_i_r_xacc:
    case Hexagon::S6_rol_i_r_acc:
    case Hexagon::S6_rol_i_r_and:
    case Hexagon::S6_rol_i_r_nac:
    case Hexagon::S6_rol_i_r_or:
    case Hexagon::S6_rol_i_r_xacc: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 8;
      case 2:
        // op: Rs32
        return 16;
      case 0:
        // op: Rx32
        return 0;
      }
      break;
    }
    case Hexagon::S2_asl_i_p_acc:
    case Hexagon::S2_asl_i_p_and:
    case Hexagon::S2_asl_i_p_nac:
    case Hexagon::S2_asl_i_p_or:
    case Hexagon::S2_asl_i_p_xacc:
    case Hexagon::S2_asr_i_p_acc:
    case Hexagon::S2_asr_i_p_and:
    case Hexagon::S2_asr_i_p_nac:
    case Hexagon::S2_asr_i_p_or:
    case Hexagon::S2_lsr_i_p_acc:
    case Hexagon::S2_lsr_i_p_and:
    case Hexagon::S2_lsr_i_p_nac:
    case Hexagon::S2_lsr_i_p_or:
    case Hexagon::S2_lsr_i_p_xacc:
    case Hexagon::S6_rol_i_p_acc:
    case Hexagon::S6_rol_i_p_and:
    case Hexagon::S6_rol_i_p_nac:
    case Hexagon::S6_rol_i_p_or:
    case Hexagon::S6_rol_i_p_xacc: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 8;
      case 2:
        // op: Rss32
        return 16;
      case 0:
        // op: Rxx32
        return 0;
      }
      break;
    }
    case Hexagon::S2_insert: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 8;
      case 4:
        // op: II
        return 5;
      case 2:
        // op: Rs32
        return 16;
      case 0:
        // op: Rx32
        return 0;
      }
      break;
    }
    case Hexagon::S2_insertp: {
      switch (OpNum) {
      case 3:
        // op: Ii
        return 8;
      case 4:
        // op: II
        return 5;
      case 2:
        // op: Rss32
        return 16;
      case 0:
        // op: Rxx32
        return 0;
      }
      break;
    }
    case Hexagon::L2_loadbsw2_pbr:
    case Hexagon::L2_loadbsw2_pcr:
    case Hexagon::L2_loadbsw2_pr:
    case Hexagon::L2_loadbzw2_pbr:
    case Hexagon::L2_loadbzw2_pcr:
    case Hexagon::L2_loadbzw2_pr:
    case Hexagon::L2_loadrb_pbr:
    case Hexagon::L2_loadrb_pcr:
    case Hexagon::L2_loadrb_pr:
    case Hexagon::L2_loadrh_pbr:
    case Hexagon::L2_loadrh_pcr:
    case Hexagon::L2_loadrh_pr:
    case Hexagon::L2_loadri_pbr:
    case Hexagon::L2_loadri_pcr:
    case Hexagon::L2_loadri_pr:
    case Hexagon::L2_loadrub_pbr:
    case Hexagon::L2_loadrub_pcr:
    case Hexagon::L2_loadrub_pr:
    case Hexagon::L2_loadruh_pbr:
    case Hexagon::L2_loadruh_pcr:
    case Hexagon::L2_loadruh_pr: {
      switch (OpNum) {
      case 3:
        // op: Mu2
        return 13;
      case 0:
        // op: Rd32
        return 0;
      case 1:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::L2_loadbsw4_pbr:
    case Hexagon::L2_loadbsw4_pcr:
    case Hexagon::L2_loadbsw4_pr:
    case Hexagon::L2_loadbzw4_pbr:
    case Hexagon::L2_loadbzw4_pcr:
    case Hexagon::L2_loadbzw4_pr:
    case Hexagon::L2_loadrd_pbr:
    case Hexagon::L2_loadrd_pcr:
    case Hexagon::L2_loadrd_pr: {
      switch (OpNum) {
      case 3:
        // op: Mu2
        return 13;
      case 0:
        // op: Rdd32
        return 0;
      case 1:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::V6_vL32Ub_ppu:
    case Hexagon::V6_vL32b_cur_ppu:
    case Hexagon::V6_vL32b_nt_cur_ppu:
    case Hexagon::V6_vL32b_nt_ppu:
    case Hexagon::V6_vL32b_nt_tmp_ppu:
    case Hexagon::V6_vL32b_ppu:
    case Hexagon::V6_vL32b_tmp_ppu: {
      switch (OpNum) {
      case 3:
        // op: Mu2
        return 13;
      case 0:
        // op: Vd32
        return 0;
      case 1:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::A5_ACS: {
      switch (OpNum) {
      case 3:
        // op: Rss32
        return 16;
      case 4:
        // op: Rtt32
        return 8;
      case 0:
        // op: Rxx32
        return 0;
      case 1:
        // op: Pe4
        return 5;
      }
      break;
    }
    case Hexagon::V6_vrmpyzbb_rx_acc:
    case Hexagon::V6_vrmpyzbub_rx_acc:
    case Hexagon::V6_vrmpyzcb_rx_acc:
    case Hexagon::V6_vrmpyzcbs_rx_acc:
    case Hexagon::V6_vrmpyznb_rx_acc: {
      switch (OpNum) {
      case 3:
        // op: Vu32
        return 8;
      case 0:
        // op: Vyyyy32
        return 0;
      case 1:
        // op: Rx8
        return 16;
      }
      break;
    }
    case Hexagon::L2_loadalignb_pi:
    case Hexagon::L2_loadalignh_pi: {
      switch (OpNum) {
      case 4:
        // op: Ii
        return 5;
      case 0:
        // op: Ryy32
        return 0;
      case 1:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::L2_ploadrbf_pi:
    case Hexagon::L2_ploadrbfnew_pi:
    case Hexagon::L2_ploadrbt_pi:
    case Hexagon::L2_ploadrbtnew_pi:
    case Hexagon::L2_ploadrhf_pi:
    case Hexagon::L2_ploadrhfnew_pi:
    case Hexagon::L2_ploadrht_pi:
    case Hexagon::L2_ploadrhtnew_pi:
    case Hexagon::L2_ploadrif_pi:
    case Hexagon::L2_ploadrifnew_pi:
    case Hexagon::L2_ploadrit_pi:
    case Hexagon::L2_ploadritnew_pi:
    case Hexagon::L2_ploadrubf_pi:
    case Hexagon::L2_ploadrubfnew_pi:
    case Hexagon::L2_ploadrubt_pi:
    case Hexagon::L2_ploadrubtnew_pi:
    case Hexagon::L2_ploadruhf_pi:
    case Hexagon::L2_ploadruhfnew_pi:
    case Hexagon::L2_ploadruht_pi:
    case Hexagon::L2_ploadruhtnew_pi: {
      switch (OpNum) {
      case 4:
        // op: Ii
        return 5;
      case 2:
        // op: Pt4
        return 9;
      case 0:
        // op: Rd32
        return 0;
      case 1:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::L2_ploadrdf_pi:
    case Hexagon::L2_ploadrdfnew_pi:
    case Hexagon::L2_ploadrdt_pi:
    case Hexagon::L2_ploadrdtnew_pi: {
      switch (OpNum) {
      case 4:
        // op: Ii
        return 5;
      case 2:
        // op: Pt4
        return 9;
      case 0:
        // op: Rdd32
        return 0;
      case 1:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::S4_vrcrotate_acc: {
      switch (OpNum) {
      case 4:
        // op: Ii
        return 5;
      case 2:
        // op: Rss32
        return 16;
      case 3:
        // op: Rt32
        return 8;
      case 0:
        // op: Rxx32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vlutvvb_oracci: {
      switch (OpNum) {
      case 4:
        // op: Ii
        return 5;
      case 2:
        // op: Vu32
        return 8;
      case 3:
        // op: Vv32
        return 16;
      case 0:
        // op: Vx32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vlutvwh_oracci: {
      switch (OpNum) {
      case 4:
        // op: Ii
        return 5;
      case 2:
        // op: Vu32
        return 8;
      case 3:
        // op: Vv32
        return 16;
      case 0:
        // op: Vxx32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vrmpybusi_acc:
    case Hexagon::V6_vrmpyubi_acc:
    case Hexagon::V6_vrsadubi_acc: {
      switch (OpNum) {
      case 4:
        // op: Ii
        return 5;
      case 2:
        // op: Vuu32
        return 8;
      case 3:
        // op: Rt32
        return 16;
      case 0:
        // op: Vxx32
        return 0;
      }
      break;
    }
    case Hexagon::V6_v6mpyhubs10_vxx:
    case Hexagon::V6_v6mpyvubs10_vxx: {
      switch (OpNum) {
      case 4:
        // op: Ii
        return 5;
      case 2:
        // op: Vuu32
        return 8;
      case 3:
        // op: Vvv32
        return 16;
      case 0:
        // op: Vxx32
        return 0;
      }
      break;
    }
    case Hexagon::L2_loadalignb_pci:
    case Hexagon::L2_loadalignh_pci: {
      switch (OpNum) {
      case 4:
        // op: Ii
        return 5;
      case 5:
        // op: Mu2
        return 13;
      case 0:
        // op: Ryy32
        return 0;
      case 1:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::L4_ploadrbf_rr:
    case Hexagon::L4_ploadrbfnew_rr:
    case Hexagon::L4_ploadrbt_rr:
    case Hexagon::L4_ploadrbtnew_rr:
    case Hexagon::L4_ploadrhf_rr:
    case Hexagon::L4_ploadrhfnew_rr:
    case Hexagon::L4_ploadrht_rr:
    case Hexagon::L4_ploadrhtnew_rr:
    case Hexagon::L4_ploadrif_rr:
    case Hexagon::L4_ploadrifnew_rr:
    case Hexagon::L4_ploadrit_rr:
    case Hexagon::L4_ploadritnew_rr:
    case Hexagon::L4_ploadrubf_rr:
    case Hexagon::L4_ploadrubfnew_rr:
    case Hexagon::L4_ploadrubt_rr:
    case Hexagon::L4_ploadrubtnew_rr:
    case Hexagon::L4_ploadruhf_rr:
    case Hexagon::L4_ploadruhfnew_rr:
    case Hexagon::L4_ploadruht_rr:
    case Hexagon::L4_ploadruhtnew_rr: {
      switch (OpNum) {
      case 4:
        // op: Ii
        return 7;
      case 1:
        // op: Pv4
        return 5;
      case 2:
        // op: Rs32
        return 16;
      case 3:
        // op: Rt32
        return 8;
      case 0:
        // op: Rd32
        return 0;
      }
      break;
    }
    case Hexagon::L4_ploadrdf_rr:
    case Hexagon::L4_ploadrdfnew_rr:
    case Hexagon::L4_ploadrdt_rr:
    case Hexagon::L4_ploadrdtnew_rr: {
      switch (OpNum) {
      case 4:
        // op: Ii
        return 7;
      case 1:
        // op: Pv4
        return 5;
      case 2:
        // op: Rs32
        return 16;
      case 3:
        // op: Rt32
        return 8;
      case 0:
        // op: Rdd32
        return 0;
      }
      break;
    }
    case Hexagon::V6_vL32b_cur_npred_pi:
    case Hexagon::V6_vL32b_cur_pred_pi:
    case Hexagon::V6_vL32b_npred_pi:
    case Hexagon::V6_vL32b_nt_cur_npred_pi:
    case Hexagon::V6_vL32b_nt_cur_pred_pi:
    case Hexagon::V6_vL32b_nt_npred_pi:
    case Hexagon::V6_vL32b_nt_pred_pi:
    case Hexagon::V6_vL32b_nt_tmp_npred_pi:
    case Hexagon::V6_vL32b_nt_tmp_pred_pi:
    case Hexagon::V6_vL32b_pred_pi:
    case Hexagon::V6_vL32b_tmp_npred_pi:
    case Hexagon::V6_vL32b_tmp_pred_pi: {
      switch (OpNum) {
      case 4:
        // op: Ii
        return 8;
      case 2:
        // op: Pv4
        return 11;
      case 0:
        // op: Vd32
        return 0;
      case 1:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::L2_loadalignb_pbr:
    case Hexagon::L2_loadalignb_pcr:
    case Hexagon::L2_loadalignb_pr:
    case Hexagon::L2_loadalignh_pbr:
    case Hexagon::L2_loadalignh_pcr:
    case Hexagon::L2_loadalignh_pr: {
      switch (OpNum) {
      case 4:
        // op: Mu2
        return 13;
      case 0:
        // op: Ryy32
        return 0;
      case 1:
        // op: Rx32
        return 16;
      }
      break;
    }
    case Hexagon::V6_vdeal:
    case Hexagon::V6_vshuff: {
      switch (OpNum) {
      case 4:
        // op: Rt32
        return 16;
      case 0:
        // op: Vy32
        return 8;
      case 1:
        // op: Vx32
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

