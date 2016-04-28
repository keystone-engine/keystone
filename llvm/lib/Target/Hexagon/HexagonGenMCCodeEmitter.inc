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
    UINT64_C(0),	// A2_addsp
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
    UINT64_C(0),	// A2_not
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
    UINT64_C(1954545664),	// A2_tfrf
    UINT64_C(1954553856),	// A2_tfrfnew
    UINT64_C(1914699776),	// A2_tfrih
    UINT64_C(1897922560),	// A2_tfril
    UINT64_C(0),	// A2_tfrp
    UINT64_C(0),	// A2_tfrpf
    UINT64_C(0),	// A2_tfrpfnew
    UINT64_C(0),	// A2_tfrpi
    UINT64_C(0),	// A2_tfrpt
    UINT64_C(0),	// A2_tfrptnew
    UINT64_C(1646264320),	// A2_tfrrcr
    UINT64_C(2013265920),	// A2_tfrsi
    UINT64_C(1946157056),	// A2_tfrt
    UINT64_C(1946165248),	// A2_tfrtnew
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
    UINT64_C(1979719648),	// A2_zxtb
    UINT64_C(1891631104),	// A2_zxth
    UINT64_C(3267362816),	// A4_addp_c
    UINT64_C(4051697664),	// A4_andn
    UINT64_C(3554672672),	// A4_andnp
    UINT64_C(3558866944),	// A4_bitsplit
    UINT64_C(2294284416),	// A4_bitspliti
    UINT64_C(0),	// A4_boundscheck
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
    UINT64_C(0),	// A4_ext_b
    UINT64_C(0),	// A4_ext_c
    UINT64_C(0),	// A4_ext_g
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
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),	// ARGEXTEND
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
    UINT64_C(0),
    UINT64_C(0),
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
    UINT64_C(0),	// C2_pxfer_map
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
    UINT64_C(1352663040),	// CALLRv3nr
    UINT64_C(1509949440),	// CALLv3nr
    UINT64_C(0),	// CONST32
    UINT64_C(0),	// CONST32_Float_Real
    UINT64_C(0),	// CONST32_Int_Real
    UINT64_C(0),	// CONST64_Float_Real
    UINT64_C(0),	// CONST64_Int_Real
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
    UINT64_C(0),
    UINT64_C(0),
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
    UINT64_C(3699376144),	// F2_dfclass
    UINT64_C(3537895424),	// F2_dfcmpeq
    UINT64_C(3537895488),	// F2_dfcmpge
    UINT64_C(3537895456),	// F2_dfcmpgt
    UINT64_C(3537895520),	// F2_dfcmpuo
    UINT64_C(3644850176),	// F2_dfimm_n
    UINT64_C(3640655872),	// F2_dfimm_p
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
    UINT64_C(0),	// FCONST32_nsdata
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),	// HEXAGON_V6_vd0_pseudo
    UINT64_C(0),	// HEXAGON_V6_vd0_pseudo_128B
    UINT64_C(1914699776),	// HI
    UINT64_C(0),	// HI_GOT
    UINT64_C(0),	// HI_GOTREL
    UINT64_C(1914699776),	// HI_L
    UINT64_C(0),	// HI_PIC
    UINT64_C(0),
    UINT64_C(1509949440),	// J2_call
    UINT64_C(1562378240),	// J2_callf
    UINT64_C(1352663040),	// J2_callr
    UINT64_C(1361051648),	// J2_callrf
    UINT64_C(1358954496),	// J2_callrt
    UINT64_C(1560281088),	// J2_callt
    UINT64_C(1476395008),	// J2_jump
    UINT64_C(1476395008),	// J2_jump_ext
    UINT64_C(1545601024),	// J2_jump_extf
    UINT64_C(1545603072),	// J2_jump_extfnew
    UINT64_C(1545607168),	// J2_jump_extfnewpt
    UINT64_C(1543503872),	// J2_jump_extt
    UINT64_C(1543505920),	// J2_jump_exttnew
    UINT64_C(1543510016),	// J2_jump_exttnewpt
    UINT64_C(1476395008),	// J2_jump_noext
    UINT64_C(1545601024),	// J2_jump_noextf
    UINT64_C(1545603072),	// J2_jump_noextfnew
    UINT64_C(1545607168),	// J2_jump_noextfnewpt
    UINT64_C(1543503872),	// J2_jump_noextt
    UINT64_C(1543505920),	// J2_jump_noexttnew
    UINT64_C(1543510016),	// J2_jump_noexttnewpt
    UINT64_C(1545601024),	// J2_jumpf
    UINT64_C(1545603072),	// J2_jumpfnew
    UINT64_C(1545607168),	// J2_jumpfnewpt
    UINT64_C(1384120320),	// J2_jumpr
    UINT64_C(1398800384),	// J2_jumprf
    UINT64_C(1398802432),	// J2_jumprfnew
    UINT64_C(1398806528),	// J2_jumprfnewpt
    UINT64_C(1631584256),	// J2_jumprgtez
    UINT64_C(1631588352),	// J2_jumprgtezpt
    UINT64_C(1639972864),	// J2_jumprltez
    UINT64_C(1639976960),	// J2_jumprltezpt
    UINT64_C(1635778560),	// J2_jumprnz
    UINT64_C(1635782656),	// J2_jumprnzpt
    UINT64_C(1396703232),	// J2_jumprt
    UINT64_C(1396705280),	// J2_jumprtnew
    UINT64_C(1396709376),	// J2_jumprtnewpt
    UINT64_C(1627389952),	// J2_jumprz
    UINT64_C(1627394048),	// J2_jumprzpt
    UINT64_C(1543503872),	// J2_jumpt
    UINT64_C(1543505920),	// J2_jumptnew
    UINT64_C(1543510016),	// J2_jumptnewpt
    UINT64_C(1761607680),	// J2_loop0i
    UINT64_C(1761607680),	// J2_loop0iext
    UINT64_C(1610612736),	// J2_loop0r
    UINT64_C(1610612736),	// J2_loop0rext
    UINT64_C(1763704832),	// J2_loop1i
    UINT64_C(1763704832),	// J2_loop1iext
    UINT64_C(1612709888),	// J2_loop1r
    UINT64_C(1612709888),	// J2_loop1rext
    UINT64_C(1772093440),	// J2_ploop1si
    UINT64_C(1621098496),	// J2_ploop1sr
    UINT64_C(1774190592),	// J2_ploop2si
    UINT64_C(1623195648),	// J2_ploop2sr
    UINT64_C(1776287744),	// J2_ploop3si
    UINT64_C(1625292800),	// J2_ploop3sr
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
    UINT64_C(1384120320),	// JMPret
    UINT64_C(1398800384),	// JMPretf
    UINT64_C(1398802432),	// JMPretfnew
    UINT64_C(1398806528),	// JMPretfnewpt
    UINT64_C(1396703232),	// JMPrett
    UINT64_C(1396705280),	// JMPrettnew
    UINT64_C(1396709376),	// JMPrettnewpt
    UINT64_C(2417885214),	// L2_deallocframe
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
    UINT64_C(0),
    UINT64_C(2566914048),	// L2_loadrb_pci
    UINT64_C(0),
    UINT64_C(2566914560),	// L2_loadrb_pcr
    UINT64_C(2600468480),	// L2_loadrb_pi
    UINT64_C(2634022912),	// L2_loadrb_pr
    UINT64_C(1224736768),	// L2_loadrbgp
    UINT64_C(2445279232),	// L2_loadrd_io
    UINT64_C(2680160256),	// L2_loadrd_pbr
    UINT64_C(0),
    UINT64_C(2579496960),	// L2_loadrd_pci
    UINT64_C(0),
    UINT64_C(2579497472),	// L2_loadrd_pcr
    UINT64_C(2613051392),	// L2_loadrd_pi
    UINT64_C(2646605824),	// L2_loadrd_pr
    UINT64_C(1237319680),	// L2_loadrdgp
    UINT64_C(2436890624),	// L2_loadrh_io
    UINT64_C(2671771648),	// L2_loadrh_pbr
    UINT64_C(0),
    UINT64_C(2571108352),	// L2_loadrh_pci
    UINT64_C(0),
    UINT64_C(2571108864),	// L2_loadrh_pcr
    UINT64_C(2604662784),	// L2_loadrh_pi
    UINT64_C(2638217216),	// L2_loadrh_pr
    UINT64_C(1228931072),	// L2_loadrhgp
    UINT64_C(2441084928),	// L2_loadri_io
    UINT64_C(2675965952),	// L2_loadri_pbr
    UINT64_C(0),
    UINT64_C(2575302656),	// L2_loadri_pci
    UINT64_C(0),
    UINT64_C(2575303168),	// L2_loadri_pcr
    UINT64_C(2608857088),	// L2_loadri_pi
    UINT64_C(2642411520),	// L2_loadri_pr
    UINT64_C(1233125376),	// L2_loadrigp
    UINT64_C(2434793472),	// L2_loadrub_io
    UINT64_C(2669674496),	// L2_loadrub_pbr
    UINT64_C(0),
    UINT64_C(2569011200),	// L2_loadrub_pci
    UINT64_C(0),
    UINT64_C(2569011712),	// L2_loadrub_pcr
    UINT64_C(2602565632),	// L2_loadrub_pi
    UINT64_C(2636120064),	// L2_loadrub_pr
    UINT64_C(1226833920),	// L2_loadrubgp
    UINT64_C(2438987776),	// L2_loadruh_io
    UINT64_C(2673868800),	// L2_loadruh_pbr
    UINT64_C(0),
    UINT64_C(2573205504),	// L2_loadruh_pci
    UINT64_C(0),
    UINT64_C(2573206016),	// L2_loadruh_pcr
    UINT64_C(2606759936),	// L2_loadruh_pi
    UINT64_C(2640314368),	// L2_loadruh_pr
    UINT64_C(1231028224),	// L2_loadruhgp
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
    UINT64_C(2449477632),	// L4_loadd_locked
    UINT64_C(1224736768),	// L4_loadrb_abs
    UINT64_C(2600472576),	// L4_loadrb_ap
    UINT64_C(973078528),	// L4_loadrb_rr
    UINT64_C(2634027008),	// L4_loadrb_ur
    UINT64_C(1237319680),	// L4_loadrd_abs
    UINT64_C(2613055488),	// L4_loadrd_ap
    UINT64_C(985661440),	// L4_loadrd_rr
    UINT64_C(2646609920),	// L4_loadrd_ur
    UINT64_C(1228931072),	// L4_loadrh_abs
    UINT64_C(2604666880),	// L4_loadrh_ap
    UINT64_C(977272832),	// L4_loadrh_rr
    UINT64_C(2638221312),	// L4_loadrh_ur
    UINT64_C(1233125376),	// L4_loadri_abs
    UINT64_C(2608861184),	// L4_loadri_ap
    UINT64_C(981467136),	// L4_loadri_rr
    UINT64_C(2642415616),	// L4_loadri_ur
    UINT64_C(1226833920),	// L4_loadrub_abs
    UINT64_C(2602569728),	// L4_loadrub_ap
    UINT64_C(975175680),	// L4_loadrub_rr
    UINT64_C(2636124160),	// L4_loadrub_ur
    UINT64_C(1231028224),	// L4_loadruh_abs
    UINT64_C(2606764032),	// L4_loadruh_ap
    UINT64_C(979369984),	// L4_loadruh_rr
    UINT64_C(2640318464),	// L4_loadruh_ur
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
    UINT64_C(2518548510),	// L4_return
    UINT64_C(2518560798),	// L4_return_f
    UINT64_C(2518558750),	// L4_return_fnew_pnt
    UINT64_C(2518562846),	// L4_return_fnew_pt
    UINT64_C(2518552606),	// L4_return_t
    UINT64_C(2518550558),	// L4_return_tnew_pnt
    UINT64_C(2518554654),	// L4_return_tnew_pt
    UINT64_C(1040187424),	// L4_sub_memopb_io
    UINT64_C(1042284576),	// L4_sub_memoph_io
    UINT64_C(1044381728),	// L4_sub_memopw_io
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
    UINT64_C(1897922560),	// LO
    UINT64_C(0),	// LO_GOT
    UINT64_C(0),	// LO_GOTREL
    UINT64_C(1897922560),	// LO_H
    UINT64_C(0),	// LO_PIC
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
    UINT64_C(0),	// M2_mpysmi
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
    UINT64_C(0),	// M2_mpyui
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
    UINT64_C(0),	// M2_vrcmpys_acc_s1
    UINT64_C(3936354432),	// M2_vrcmpys_acc_s1_h
    UINT64_C(3940548736),	// M2_vrcmpys_acc_s1_l
    UINT64_C(0),	// M2_vrcmpys_s1
    UINT64_C(3902800000),	// M2_vrcmpys_s1_h
    UINT64_C(3906994304),	// M2_vrcmpys_s1_l
    UINT64_C(0),	// M2_vrcmpys_s1rp
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
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(1509949440),	// RESTORE_DEALLOC_BEFORE_TAILCALL_V4
    UINT64_C(1509949440),	// RESTORE_DEALLOC_BEFORE_TAILCALL_V4_EXT
    UINT64_C(1476395008),	// RESTORE_DEALLOC_RET_JMP_V4
    UINT64_C(1476395008),	// RESTORE_DEALLOC_RET_JMP_V4_EXT
    UINT64_C(3288334336),	// S2_addasl_rrri
    UINT64_C(2694643712),	// S2_allocframe
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
    UINT64_C(0),	// S2_asr_i_p_rnd_goodsyntax
    UINT64_C(2348810240),	// S2_asr_i_r
    UINT64_C(2382364800),	// S2_asr_i_r_acc
    UINT64_C(2386558976),	// S2_asr_i_r_and
    UINT64_C(2382364672),	// S2_asr_i_r_nac
    UINT64_C(2386559104),	// S2_asr_i_r_or
    UINT64_C(2353004544),	// S2_asr_i_r_rnd
    UINT64_C(0),	// S2_asr_i_r_rnd_goodsyntax
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
    UINT64_C(3265265664),	// S2_cabacencbin
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
    UINT64_C(0),
    UINT64_C(2835349504),	// S2_storerb_pci
    UINT64_C(0),
    UINT64_C(2835349506),	// S2_storerb_pcr
    UINT64_C(2868903936),	// S2_storerb_pi
    UINT64_C(2902458368),	// S2_storerb_pr
    UINT64_C(1207959552),	// S2_storerbabs
    UINT64_C(1207959552),	// S2_storerbgp
    UINT64_C(2711617536),	// S2_storerbnew_io
    UINT64_C(2946498560),	// S2_storerbnew_pbr
    UINT64_C(2845835264),	// S2_storerbnew_pci
    UINT64_C(2845835266),	// S2_storerbnew_pcr
    UINT64_C(2879389696),	// S2_storerbnew_pi
    UINT64_C(2912944128),	// S2_storerbnew_pr
    UINT64_C(1218445312),	// S2_storerbnewabs
    UINT64_C(1218445312),	// S2_storerbnewgp
    UINT64_C(2713714688),	// S2_storerd_io
    UINT64_C(2948595712),	// S2_storerd_pbr
    UINT64_C(0),
    UINT64_C(2847932416),	// S2_storerd_pci
    UINT64_C(0),
    UINT64_C(2847932418),	// S2_storerd_pcr
    UINT64_C(2881486848),	// S2_storerd_pi
    UINT64_C(2915041280),	// S2_storerd_pr
    UINT64_C(1220542464),	// S2_storerdabs
    UINT64_C(1220542464),	// S2_storerdgp
    UINT64_C(2707423232),	// S2_storerf_io
    UINT64_C(2942304256),	// S2_storerf_pbr
    UINT64_C(0),
    UINT64_C(2841640960),	// S2_storerf_pci
    UINT64_C(0),
    UINT64_C(2841640962),	// S2_storerf_pcr
    UINT64_C(2875195392),	// S2_storerf_pi
    UINT64_C(2908749824),	// S2_storerf_pr
    UINT64_C(1214251008),	// S2_storerfabs
    UINT64_C(1214251008),	// S2_storerfgp
    UINT64_C(2705326080),	// S2_storerh_io
    UINT64_C(2940207104),	// S2_storerh_pbr
    UINT64_C(0),
    UINT64_C(2839543808),	// S2_storerh_pci
    UINT64_C(0),
    UINT64_C(2839543810),	// S2_storerh_pcr
    UINT64_C(2873098240),	// S2_storerh_pi
    UINT64_C(2906652672),	// S2_storerh_pr
    UINT64_C(1212153856),	// S2_storerhabs
    UINT64_C(1212153856),	// S2_storerhgp
    UINT64_C(2711619584),	// S2_storerhnew_io
    UINT64_C(2946500608),	// S2_storerhnew_pbr
    UINT64_C(2845837312),	// S2_storerhnew_pci
    UINT64_C(2845837314),	// S2_storerhnew_pcr
    UINT64_C(2879391744),	// S2_storerhnew_pi
    UINT64_C(2912946176),	// S2_storerhnew_pr
    UINT64_C(1218447360),	// S2_storerhnewabs
    UINT64_C(1218447360),	// S2_storerhnewgp
    UINT64_C(2709520384),	// S2_storeri_io
    UINT64_C(2944401408),	// S2_storeri_pbr
    UINT64_C(0),
    UINT64_C(2843738112),	// S2_storeri_pci
    UINT64_C(0),
    UINT64_C(2843738114),	// S2_storeri_pcr
    UINT64_C(2877292544),	// S2_storeri_pi
    UINT64_C(2910846976),	// S2_storeri_pr
    UINT64_C(1216348160),	// S2_storeriabs
    UINT64_C(1216348160),	// S2_storerigp
    UINT64_C(2711621632),	// S2_storerinew_io
    UINT64_C(2946502656),	// S2_storerinew_pbr
    UINT64_C(2845839360),	// S2_storerinew_pci
    UINT64_C(2845839362),	// S2_storerinew_pcr
    UINT64_C(2879393792),	// S2_storerinew_pi
    UINT64_C(2912948224),	// S2_storerinew_pr
    UINT64_C(1218449408),	// S2_storerinewabs
    UINT64_C(1218449408),	// S2_storerinewgp
    UINT64_C(2694840320),	// S2_storew_locked
    UINT64_C(2357198848),	// S2_svsathb
    UINT64_C(2357198912),	// S2_svsathub
    UINT64_C(2264924160),	// S2_tableidxb
    UINT64_C(0),
    UINT64_C(2277507072),	// S2_tableidxd
    UINT64_C(0),
    UINT64_C(2269118464),	// S2_tableidxh
    UINT64_C(0),
    UINT64_C(2273312768),	// S2_tableidxw
    UINT64_C(0),
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
    UINT64_C(0),	// S5_asrhub_rnd_sat_goodsyntax
    UINT64_C(2287992992),	// S5_asrhub_sat
    UINT64_C(2287992928),	// S5_popcountp
    UINT64_C(2149580800),	// S5_vasrhrnd
    UINT64_C(0),	// S5_vasrhrnd_goodsyntax
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
    UINT64_C(1509949440),	// SAVE_REGISTERS_CALL_V4
    UINT64_C(1509949440),	// SAVE_REGISTERS_CALL_V4_EXT
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
    UINT64_C(0),	// TFRI64_V2_ext
    UINT64_C(0),	// TFRI64_V4
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),	// V4_SA1_addi
    UINT64_C(6144),	// V4_SA1_addrx
    UINT64_C(3072),	// V4_SA1_addsp
    UINT64_C(4608),	// V4_SA1_and1
    UINT64_C(6768),	// V4_SA1_clrf
    UINT64_C(6736),	// V4_SA1_clrfnew
    UINT64_C(6752),	// V4_SA1_clrt
    UINT64_C(6720),	// V4_SA1_clrtnew
    UINT64_C(6400),	// V4_SA1_cmpeqi
    UINT64_C(7168),	// V4_SA1_combine0i
    UINT64_C(7176),	// V4_SA1_combine1i
    UINT64_C(7184),	// V4_SA1_combine2i
    UINT64_C(7192),	// V4_SA1_combine3i
    UINT64_C(7432),	// V4_SA1_combinerz
    UINT64_C(7424),	// V4_SA1_combinezr
    UINT64_C(4864),	// V4_SA1_dec
    UINT64_C(4352),	// V4_SA1_inc
    UINT64_C(2048),	// V4_SA1_seti
    UINT64_C(6656),	// V4_SA1_setin1
    UINT64_C(5376),	// V4_SA1_sxtb
    UINT64_C(5120),	// V4_SA1_sxth
    UINT64_C(4096),	// V4_SA1_tfr
    UINT64_C(5888),	// V4_SA1_zxtb
    UINT64_C(5632),	// V4_SA1_zxth
    UINT64_C(0),	// V4_SL1_loadri_io
    UINT64_C(4096),	// V4_SL1_loadrub_io
    UINT64_C(7936),	// V4_SL2_deallocframe
    UINT64_C(8128),	// V4_SL2_jumpr31
    UINT64_C(8133),	// V4_SL2_jumpr31_f
    UINT64_C(8135),	// V4_SL2_jumpr31_fnew
    UINT64_C(8132),	// V4_SL2_jumpr31_t
    UINT64_C(8134),	// V4_SL2_jumpr31_tnew
    UINT64_C(4096),	// V4_SL2_loadrb_io
    UINT64_C(7680),	// V4_SL2_loadrd_sp
    UINT64_C(0),	// V4_SL2_loadrh_io
    UINT64_C(7168),	// V4_SL2_loadri_sp
    UINT64_C(2048),	// V4_SL2_loadruh_io
    UINT64_C(8000),	// V4_SL2_return
    UINT64_C(8005),	// V4_SL2_return_f
    UINT64_C(8007),	// V4_SL2_return_fnew
    UINT64_C(8004),	// V4_SL2_return_t
    UINT64_C(8006),	// V4_SL2_return_tnew
    UINT64_C(4096),	// V4_SS1_storeb_io
    UINT64_C(0),	// V4_SS1_storew_io
    UINT64_C(7168),	// V4_SS2_allocframe
    UINT64_C(4608),	// V4_SS2_storebi0
    UINT64_C(4864),	// V4_SS2_storebi1
    UINT64_C(2560),	// V4_SS2_stored_sp
    UINT64_C(0),	// V4_SS2_storeh_io
    UINT64_C(2048),	// V4_SS2_storew_sp
    UINT64_C(4096),	// V4_SS2_storewi0
    UINT64_C(4352),	// V4_SS2_storewi1
    UINT64_C(2449473568),	// V6_extractw
    UINT64_C(2449473568),	// V6_extractw_128B
    UINT64_C(429916192),	// V6_lvsplatw
    UINT64_C(429916192),	// V6_lvsplatw_128B
    UINT64_C(503513088),	// V6_pred_and
    UINT64_C(503513088),	// V6_pred_and_128B
    UINT64_C(503513108),	// V6_pred_and_n
    UINT64_C(503513108),	// V6_pred_and_n_128B
    UINT64_C(503513096),	// V6_pred_not
    UINT64_C(503513096),	// V6_pred_not_128B
    UINT64_C(503513092),	// V6_pred_or
    UINT64_C(503513092),	// V6_pred_or_128B
    UINT64_C(503513104),	// V6_pred_or_n
    UINT64_C(503513104),	// V6_pred_or_n_128B
    UINT64_C(429916228),	// V6_pred_scalar2
    UINT64_C(429916228),	// V6_pred_scalar2_128B
    UINT64_C(503513100),	// V6_pred_xor
    UINT64_C(503513100),	// V6_pred_xor_128B
    UINT64_C(671088864),	// V6_vL32Ub_ai
    UINT64_C(671088864),	// V6_vL32Ub_ai_128B
    UINT64_C(687866080),	// V6_vL32Ub_pi
    UINT64_C(687866080),	// V6_vL32Ub_pi_128B
    UINT64_C(721420512),	// V6_vL32Ub_ppu
    UINT64_C(671088640),	// V6_vL32b_ai
    UINT64_C(671088640),	// V6_vL32b_ai_128B
    UINT64_C(671088672),	// V6_vL32b_cur_ai
    UINT64_C(671088672),	// V6_vL32b_cur_ai_128B
    UINT64_C(687865888),	// V6_vL32b_cur_pi
    UINT64_C(687865888),	// V6_vL32b_cur_pi_128B
    UINT64_C(721420320),	// V6_vL32b_cur_ppu
    UINT64_C(675282944),	// V6_vL32b_nt_ai
    UINT64_C(675282944),	// V6_vL32b_nt_ai_128B
    UINT64_C(675282976),	// V6_vL32b_nt_cur_ai
    UINT64_C(675282976),	// V6_vL32b_nt_cur_ai_128B
    UINT64_C(692060192),	// V6_vL32b_nt_cur_pi
    UINT64_C(692060192),	// V6_vL32b_nt_cur_pi_128B
    UINT64_C(725614624),	// V6_vL32b_nt_cur_ppu
    UINT64_C(692060160),	// V6_vL32b_nt_pi
    UINT64_C(692060160),	// V6_vL32b_nt_pi_128B
    UINT64_C(725614592),	// V6_vL32b_nt_ppu
    UINT64_C(675283008),	// V6_vL32b_nt_tmp_ai
    UINT64_C(675283008),	// V6_vL32b_nt_tmp_ai_128B
    UINT64_C(692060224),	// V6_vL32b_nt_tmp_pi
    UINT64_C(692060224),	// V6_vL32b_nt_tmp_pi_128B
    UINT64_C(725614656),	// V6_vL32b_nt_tmp_ppu
    UINT64_C(687865856),	// V6_vL32b_pi
    UINT64_C(687865856),	// V6_vL32b_pi_128B
    UINT64_C(721420288),	// V6_vL32b_ppu
    UINT64_C(671088704),	// V6_vL32b_tmp_ai
    UINT64_C(671088704),	// V6_vL32b_tmp_ai_128B
    UINT64_C(687865920),	// V6_vL32b_tmp_pi
    UINT64_C(687865920),	// V6_vL32b_tmp_pi_128B
    UINT64_C(721420352),	// V6_vL32b_tmp_ppu
    UINT64_C(673186016),	// V6_vS32Ub_ai
    UINT64_C(673186016),	// V6_vS32Ub_ai_128B
    UINT64_C(681574624),	// V6_vS32Ub_npred_ai
    UINT64_C(681574624),	// V6_vS32Ub_npred_ai_128B
    UINT64_C(698351840),	// V6_vS32Ub_npred_pi
    UINT64_C(698351840),	// V6_vS32Ub_npred_pi_128B
    UINT64_C(731906272),	// V6_vS32Ub_npred_ppu
    UINT64_C(689963232),	// V6_vS32Ub_pi
    UINT64_C(689963232),	// V6_vS32Ub_pi_128B
    UINT64_C(723517664),	// V6_vS32Ub_ppu
    UINT64_C(681574592),	// V6_vS32Ub_pred_ai
    UINT64_C(681574592),	// V6_vS32Ub_pred_ai_128B
    UINT64_C(698351808),	// V6_vS32Ub_pred_pi
    UINT64_C(698351808),	// V6_vS32Ub_pred_pi_128B
    UINT64_C(731906240),	// V6_vS32Ub_pred_ppu
    UINT64_C(673185792),	// V6_vS32b_ai
    UINT64_C(673185792),	// V6_vS32b_ai_128B
    UINT64_C(673185824),	// V6_vS32b_new_ai
    UINT64_C(673185824),	// V6_vS32b_new_ai_128B
    UINT64_C(681574504),	// V6_vS32b_new_npred_ai
    UINT64_C(681574504),	// V6_vS32b_new_npred_ai_128B
    UINT64_C(698351720),	// V6_vS32b_new_npred_pi
    UINT64_C(698351720),	// V6_vS32b_new_npred_pi_128B
    UINT64_C(731906152),	// V6_vS32b_new_npred_ppu
    UINT64_C(689963040),	// V6_vS32b_new_pi
    UINT64_C(689963040),	// V6_vS32b_new_pi_128B
    UINT64_C(723517472),	// V6_vS32b_new_ppu
    UINT64_C(681574464),	// V6_vS32b_new_pred_ai
    UINT64_C(681574464),	// V6_vS32b_new_pred_ai_128B
    UINT64_C(698351680),	// V6_vS32b_new_pred_pi
    UINT64_C(698351680),	// V6_vS32b_new_pred_pi_128B
    UINT64_C(731906112),	// V6_vS32b_new_pred_ppu
    UINT64_C(681574432),	// V6_vS32b_npred_ai
    UINT64_C(681574432),	// V6_vS32b_npred_ai_128B
    UINT64_C(698351648),	// V6_vS32b_npred_pi
    UINT64_C(698351648),	// V6_vS32b_npred_pi_128B
    UINT64_C(731906080),	// V6_vS32b_npred_ppu
    UINT64_C(679477280),	// V6_vS32b_nqpred_ai
    UINT64_C(679477280),	// V6_vS32b_nqpred_ai_128B
    UINT64_C(696254496),	// V6_vS32b_nqpred_pi
    UINT64_C(696254496),	// V6_vS32b_nqpred_pi_128B
    UINT64_C(729808928),	// V6_vS32b_nqpred_ppu
    UINT64_C(677380096),	// V6_vS32b_nt_ai
    UINT64_C(677380096),	// V6_vS32b_nt_ai_128B
    UINT64_C(677380128),	// V6_vS32b_nt_new_ai
    UINT64_C(677380128),	// V6_vS32b_nt_new_ai_128B
    UINT64_C(685768824),	// V6_vS32b_nt_new_npred_ai
    UINT64_C(685768824),	// V6_vS32b_nt_new_npred_ai_128B
    UINT64_C(702546040),	// V6_vS32b_nt_new_npred_pi
    UINT64_C(702546040),	// V6_vS32b_nt_new_npred_pi_128B
    UINT64_C(736100472),	// V6_vS32b_nt_new_npred_ppu
    UINT64_C(694157344),	// V6_vS32b_nt_new_pi
    UINT64_C(694157344),	// V6_vS32b_nt_new_pi_128B
    UINT64_C(727711776),	// V6_vS32b_nt_new_ppu
    UINT64_C(685768784),	// V6_vS32b_nt_new_pred_ai
    UINT64_C(685768784),	// V6_vS32b_nt_new_pred_ai_128B
    UINT64_C(702546000),	// V6_vS32b_nt_new_pred_pi
    UINT64_C(702546000),	// V6_vS32b_nt_new_pred_pi_128B
    UINT64_C(736100432),	// V6_vS32b_nt_new_pred_ppu
    UINT64_C(685768736),	// V6_vS32b_nt_npred_ai
    UINT64_C(685768736),	// V6_vS32b_nt_npred_ai_128B
    UINT64_C(702545952),	// V6_vS32b_nt_npred_pi
    UINT64_C(702545952),	// V6_vS32b_nt_npred_pi_128B
    UINT64_C(736100384),	// V6_vS32b_nt_npred_ppu
    UINT64_C(683671584),	// V6_vS32b_nt_nqpred_ai
    UINT64_C(683671584),	// V6_vS32b_nt_nqpred_ai_128B
    UINT64_C(700448800),	// V6_vS32b_nt_nqpred_pi
    UINT64_C(700448800),	// V6_vS32b_nt_nqpred_pi_128B
    UINT64_C(734003232),	// V6_vS32b_nt_nqpred_ppu
    UINT64_C(694157312),	// V6_vS32b_nt_pi
    UINT64_C(694157312),	// V6_vS32b_nt_pi_128B
    UINT64_C(727711744),	// V6_vS32b_nt_ppu
    UINT64_C(685768704),	// V6_vS32b_nt_pred_ai
    UINT64_C(685768704),	// V6_vS32b_nt_pred_ai_128B
    UINT64_C(702545920),	// V6_vS32b_nt_pred_pi
    UINT64_C(702545920),	// V6_vS32b_nt_pred_pi_128B
    UINT64_C(736100352),	// V6_vS32b_nt_pred_ppu
    UINT64_C(683671552),	// V6_vS32b_nt_qpred_ai
    UINT64_C(683671552),	// V6_vS32b_nt_qpred_ai_128B
    UINT64_C(700448768),	// V6_vS32b_nt_qpred_pi
    UINT64_C(700448768),	// V6_vS32b_nt_qpred_pi_128B
    UINT64_C(734003200),	// V6_vS32b_nt_qpred_ppu
    UINT64_C(689963008),	// V6_vS32b_pi
    UINT64_C(689963008),	// V6_vS32b_pi_128B
    UINT64_C(723517440),	// V6_vS32b_ppu
    UINT64_C(681574400),	// V6_vS32b_pred_ai
    UINT64_C(681574400),	// V6_vS32b_pred_ai_128B
    UINT64_C(698351616),	// V6_vS32b_pred_pi
    UINT64_C(698351616),	// V6_vS32b_pred_pi_128B
    UINT64_C(731906048),	// V6_vS32b_pred_ppu
    UINT64_C(679477248),	// V6_vS32b_qpred_ai
    UINT64_C(679477248),	// V6_vS32b_qpred_ai_128B
    UINT64_C(696254464),	// V6_vS32b_qpred_pi
    UINT64_C(696254464),	// V6_vS32b_qpred_pi_128B
    UINT64_C(729808896),	// V6_vS32b_qpred_ppu
    UINT64_C(482344992),	// V6_vabsdiffh
    UINT64_C(482344992),	// V6_vabsdiffh_128B
    UINT64_C(482344960),	// V6_vabsdiffub
    UINT64_C(482344960),	// V6_vabsdiffub_128B
    UINT64_C(482345024),	// V6_vabsdiffuh
    UINT64_C(482345024),	// V6_vabsdiffuh_128B
    UINT64_C(482345056),	// V6_vabsdiffw
    UINT64_C(482345056),	// V6_vabsdiffw_128B
    UINT64_C(503316480),	// V6_vabsh
    UINT64_C(503316480),	// V6_vabsh_128B
    UINT64_C(503316512),	// V6_vabsh_sat
    UINT64_C(503316512),	// V6_vabsh_sat_128B
    UINT64_C(503316544),	// V6_vabsw
    UINT64_C(503316544),	// V6_vabsw_128B
    UINT64_C(503316576),	// V6_vabsw_sat
    UINT64_C(503316576),	// V6_vabsw_sat_128B
    UINT64_C(530579648),	// V6_vaddb
    UINT64_C(530579648),	// V6_vaddb_128B
    UINT64_C(476053632),	// V6_vaddb_dv
    UINT64_C(476053632),	// V6_vaddb_dv_128B
    UINT64_C(503390304),	// V6_vaddbnq
    UINT64_C(503390304),	// V6_vaddbnq_128B
    UINT64_C(503390208),	// V6_vaddbq
    UINT64_C(503390208),	// V6_vaddbq_128B
    UINT64_C(530579680),	// V6_vaddh
    UINT64_C(530579680),	// V6_vaddh_128B
    UINT64_C(476053664),	// V6_vaddh_dv
    UINT64_C(476053664),	// V6_vaddh_dv_128B
    UINT64_C(503390336),	// V6_vaddhnq
    UINT64_C(503390336),	// V6_vaddhnq_128B
    UINT64_C(503390240),	// V6_vaddhq
    UINT64_C(503390240),	// V6_vaddhq_128B
    UINT64_C(473956448),	// V6_vaddhsat
    UINT64_C(473956448),	// V6_vaddhsat_128B
    UINT64_C(478150688),	// V6_vaddhsat_dv
    UINT64_C(478150688),	// V6_vaddhsat_dv_128B
    UINT64_C(480247936),	// V6_vaddhw
    UINT64_C(480247936),	// V6_vaddhw_128B
    UINT64_C(480247872),	// V6_vaddubh
    UINT64_C(480247872),	// V6_vaddubh_128B
    UINT64_C(473956384),	// V6_vaddubsat
    UINT64_C(473956384),	// V6_vaddubsat_128B
    UINT64_C(476053728),	// V6_vaddubsat_dv
    UINT64_C(476053728),	// V6_vaddubsat_dv_128B
    UINT64_C(473956416),	// V6_vadduhsat
    UINT64_C(473956416),	// V6_vadduhsat_128B
    UINT64_C(478150656),	// V6_vadduhsat_dv
    UINT64_C(478150656),	// V6_vadduhsat_dv_128B
    UINT64_C(480247904),	// V6_vadduhw
    UINT64_C(480247904),	// V6_vadduhw_128B
    UINT64_C(473956352),	// V6_vaddw
    UINT64_C(473956352),	// V6_vaddw_128B
    UINT64_C(476053696),	// V6_vaddw_dv
    UINT64_C(476053696),	// V6_vaddw_dv_128B
    UINT64_C(503390368),	// V6_vaddwnq
    UINT64_C(503390368),	// V6_vaddwnq_128B
    UINT64_C(503390272),	// V6_vaddwq
    UINT64_C(503390272),	// V6_vaddwq_128B
    UINT64_C(473956480),	// V6_vaddwsat
    UINT64_C(473956480),	// V6_vaddwsat_128B
    UINT64_C(478150720),	// V6_vaddwsat_dv
    UINT64_C(478150720),	// V6_vaddwsat_dv_128B
    UINT64_C(452984832),	// V6_valignb
    UINT64_C(452984832),	// V6_valignb_128B
    UINT64_C(505421824),	// V6_valignbi
    UINT64_C(505421824),	// V6_valignbi_128B
    UINT64_C(471859360),	// V6_vand
    UINT64_C(471859360),	// V6_vand_128B
    UINT64_C(429916320),	// V6_vandqrt
    UINT64_C(429916320),	// V6_vandqrt_128B
    UINT64_C(425730144),	// V6_vandqrt_acc
    UINT64_C(425730144),	// V6_vandqrt_acc_128B
    UINT64_C(429916232),	// V6_vandvrt
    UINT64_C(429916232),	// V6_vandvrt_128B
    UINT64_C(425730176),	// V6_vandvrt_acc
    UINT64_C(425730176),	// V6_vandvrt_acc_128B
    UINT64_C(427819008),	// V6_vaslh
    UINT64_C(427819008),	// V6_vaslh_128B
    UINT64_C(530579616),	// V6_vaslhv
    UINT64_C(530579616),	// V6_vaslhv_128B
    UINT64_C(425722080),	// V6_vaslw
    UINT64_C(425722080),	// V6_vaslw_128B
    UINT64_C(425730112),	// V6_vaslw_acc
    UINT64_C(425730112),	// V6_vaslw_acc_128B
    UINT64_C(530579584),	// V6_vaslwv
    UINT64_C(530579584),	// V6_vaslwv_128B
    UINT64_C(425722048),	// V6_vasrh
    UINT64_C(425722048),	// V6_vasrh_128B
    UINT64_C(452993024),	// V6_vasrhbrndsat
    UINT64_C(452993024),	// V6_vasrhbrndsat_128B
    UINT64_C(452985056),	// V6_vasrhubrndsat
    UINT64_C(452985056),	// V6_vasrhubrndsat_128B
    UINT64_C(452985024),	// V6_vasrhubsat
    UINT64_C(452985024),	// V6_vasrhubsat_128B
    UINT64_C(530579552),	// V6_vasrhv
    UINT64_C(530579552),	// V6_vasrhv_128B
    UINT64_C(425722016),	// V6_vasrw
    UINT64_C(425722016),	// V6_vasrw_128B
    UINT64_C(425730208),	// V6_vasrw_acc
    UINT64_C(425730208),	// V6_vasrw_acc_128B
    UINT64_C(452984896),	// V6_vasrwh
    UINT64_C(452984896),	// V6_vasrwh_128B
    UINT64_C(452984960),	// V6_vasrwhrndsat
    UINT64_C(452984960),	// V6_vasrwhrndsat_128B
    UINT64_C(452984928),	// V6_vasrwhsat
    UINT64_C(452984928),	// V6_vasrwhsat_128B
    UINT64_C(452984992),	// V6_vasrwuhsat
    UINT64_C(452984992),	// V6_vasrwuhsat_128B
    UINT64_C(530579456),	// V6_vasrwv
    UINT64_C(530579456),	// V6_vasrwv_128B
    UINT64_C(503521504),	// V6_vassign
    UINT64_C(503521504),	// V6_vassign_128B
    UINT64_C(482345152),	// V6_vavgh
    UINT64_C(482345152),	// V6_vavgh_128B
    UINT64_C(484442272),	// V6_vavghrnd
    UINT64_C(484442272),	// V6_vavghrnd_128B
    UINT64_C(482345088),	// V6_vavgub
    UINT64_C(482345088),	// V6_vavgub_128B
    UINT64_C(484442208),	// V6_vavgubrnd
    UINT64_C(484442208),	// V6_vavgubrnd_128B
    UINT64_C(482345120),	// V6_vavguh
    UINT64_C(482345120),	// V6_vavguh_128B
    UINT64_C(484442240),	// V6_vavguhrnd
    UINT64_C(484442240),	// V6_vavguhrnd_128B
    UINT64_C(482345184),	// V6_vavgw
    UINT64_C(482345184),	// V6_vavgw_128B
    UINT64_C(484442304),	// V6_vavgwrnd
    UINT64_C(484442304),	// V6_vavgwrnd_128B
    UINT64_C(442499072),	// V6_vccombine
    UINT64_C(442499072),	// V6_vccombine_128B
    UINT64_C(503447776),	// V6_vcl0h
    UINT64_C(503447776),	// V6_vcl0h_128B
    UINT64_C(503447712),	// V6_vcl0w
    UINT64_C(503447712),	// V6_vcl0w_128B
    UINT64_C(436207616),	// V6_vcmov
    UINT64_C(436207616),	// V6_vcmov_128B
    UINT64_C(524288224),	// V6_vcombine
    UINT64_C(524288224),	// V6_vcombine_128B
    UINT64_C(434118720),	// V6_vdeal
    UINT64_C(434118720),	// V6_vdeal_128B
    UINT64_C(503316704),	// V6_vdealb
    UINT64_C(522191072),	// V6_vdealb4w
    UINT64_C(522191072),	// V6_vdealb4w_128B
    UINT64_C(503316704),	// V6_vdealb_128B
    UINT64_C(503316672),	// V6_vdealh
    UINT64_C(503316672),	// V6_vdealh_128B
    UINT64_C(452993152),	// V6_vdealvdd
    UINT64_C(452993152),	// V6_vdealvdd_128B
    UINT64_C(522190880),	// V6_vdelta
    UINT64_C(522190880),	// V6_vdelta_128B
    UINT64_C(419430592),	// V6_vdmpybus
    UINT64_C(419430592),	// V6_vdmpybus_128B
    UINT64_C(419438784),	// V6_vdmpybus_acc
    UINT64_C(419438784),	// V6_vdmpybus_acc_128B
    UINT64_C(419430624),	// V6_vdmpybus_dv
    UINT64_C(419430624),	// V6_vdmpybus_dv_128B
    UINT64_C(419438816),	// V6_vdmpybus_dv_acc
    UINT64_C(419438816),	// V6_vdmpybus_dv_acc_128B
    UINT64_C(419430464),	// V6_vdmpyhb
    UINT64_C(419430464),	// V6_vdmpyhb_128B
    UINT64_C(419438688),	// V6_vdmpyhb_acc
    UINT64_C(419438688),	// V6_vdmpyhb_acc_128B
    UINT64_C(421527680),	// V6_vdmpyhb_dv
    UINT64_C(421527680),	// V6_vdmpyhb_dv_128B
    UINT64_C(421535872),	// V6_vdmpyhb_dv_acc
    UINT64_C(421535872),	// V6_vdmpyhb_dv_acc_128B
    UINT64_C(421527648),	// V6_vdmpyhisat
    UINT64_C(421527648),	// V6_vdmpyhisat_128B
    UINT64_C(421535808),	// V6_vdmpyhisat_acc
    UINT64_C(421535808),	// V6_vdmpyhisat_acc_128B
    UINT64_C(421527616),	// V6_vdmpyhsat
    UINT64_C(421527616),	// V6_vdmpyhsat_128B
    UINT64_C(421535840),	// V6_vdmpyhsat_acc
    UINT64_C(421535840),	// V6_vdmpyhsat_acc_128B
    UINT64_C(421527584),	// V6_vdmpyhsuisat
    UINT64_C(421527584),	// V6_vdmpyhsuisat_128B
    UINT64_C(421535776),	// V6_vdmpyhsuisat_acc
    UINT64_C(421535776),	// V6_vdmpyhsuisat_acc_128B
    UINT64_C(421527552),	// V6_vdmpyhsusat
    UINT64_C(421527552),	// V6_vdmpyhsusat_128B
    UINT64_C(421535744),	// V6_vdmpyhsusat_acc
    UINT64_C(421535744),	// V6_vdmpyhsusat_acc_128B
    UINT64_C(469762144),	// V6_vdmpyhvsat
    UINT64_C(469762144),	// V6_vdmpyhvsat_128B
    UINT64_C(469770336),	// V6_vdmpyhvsat_acc
    UINT64_C(469770336),	// V6_vdmpyhvsat_acc_128B
    UINT64_C(419430560),	// V6_vdsaduh
    UINT64_C(419430560),	// V6_vdsaduh_128B
    UINT64_C(425730048),	// V6_vdsaduh_acc
    UINT64_C(425730048),	// V6_vdsaduh_acc_128B
    UINT64_C(528482304),	// V6_veqb
    UINT64_C(528482304),	// V6_veqb_128B
    UINT64_C(478158848),	// V6_veqb_and
    UINT64_C(478158848),	// V6_veqb_and_128B
    UINT64_C(478158912),	// V6_veqb_or
    UINT64_C(478158912),	// V6_veqb_or_128B
    UINT64_C(478158976),	// V6_veqb_xor
    UINT64_C(478158976),	// V6_veqb_xor_128B
    UINT64_C(528482308),	// V6_veqh
    UINT64_C(528482308),	// V6_veqh_128B
    UINT64_C(478158852),	// V6_veqh_and
    UINT64_C(478158852),	// V6_veqh_and_128B
    UINT64_C(478158916),	// V6_veqh_or
    UINT64_C(478158916),	// V6_veqh_or_128B
    UINT64_C(478158980),	// V6_veqh_xor
    UINT64_C(478158980),	// V6_veqh_xor_128B
    UINT64_C(528482312),	// V6_veqw
    UINT64_C(528482312),	// V6_veqw_128B
    UINT64_C(478158856),	// V6_veqw_and
    UINT64_C(478158856),	// V6_veqw_and_128B
    UINT64_C(478158920),	// V6_veqw_or
    UINT64_C(478158920),	// V6_veqw_or_128B
    UINT64_C(478158984),	// V6_veqw_xor
    UINT64_C(478158984),	// V6_veqw_xor_128B
    UINT64_C(528482320),	// V6_vgtb
    UINT64_C(528482320),	// V6_vgtb_128B
    UINT64_C(478158864),	// V6_vgtb_and
    UINT64_C(478158864),	// V6_vgtb_and_128B
    UINT64_C(478158928),	// V6_vgtb_or
    UINT64_C(478158928),	// V6_vgtb_or_128B
    UINT64_C(478158992),	// V6_vgtb_xor
    UINT64_C(478158992),	// V6_vgtb_xor_128B
    UINT64_C(528482324),	// V6_vgth
    UINT64_C(528482324),	// V6_vgth_128B
    UINT64_C(478158868),	// V6_vgth_and
    UINT64_C(478158868),	// V6_vgth_and_128B
    UINT64_C(478158932),	// V6_vgth_or
    UINT64_C(478158932),	// V6_vgth_or_128B
    UINT64_C(478158996),	// V6_vgth_xor
    UINT64_C(478158996),	// V6_vgth_xor_128B
    UINT64_C(528482336),	// V6_vgtub
    UINT64_C(528482336),	// V6_vgtub_128B
    UINT64_C(478158880),	// V6_vgtub_and
    UINT64_C(478158880),	// V6_vgtub_and_128B
    UINT64_C(478158944),	// V6_vgtub_or
    UINT64_C(478158944),	// V6_vgtub_or_128B
    UINT64_C(478159008),	// V6_vgtub_xor
    UINT64_C(478159008),	// V6_vgtub_xor_128B
    UINT64_C(528482340),	// V6_vgtuh
    UINT64_C(528482340),	// V6_vgtuh_128B
    UINT64_C(478158884),	// V6_vgtuh_and
    UINT64_C(478158884),	// V6_vgtuh_and_128B
    UINT64_C(478158948),	// V6_vgtuh_or
    UINT64_C(478158948),	// V6_vgtuh_or_128B
    UINT64_C(478159012),	// V6_vgtuh_xor
    UINT64_C(478159012),	// V6_vgtuh_xor_128B
    UINT64_C(528482344),	// V6_vgtuw
    UINT64_C(528482344),	// V6_vgtuw_128B
    UINT64_C(478158888),	// V6_vgtuw_and
    UINT64_C(478158888),	// V6_vgtuw_and_128B
    UINT64_C(478158952),	// V6_vgtuw_or
    UINT64_C(478158952),	// V6_vgtuw_or_128B
    UINT64_C(478159016),	// V6_vgtuw_xor
    UINT64_C(478159016),	// V6_vgtuw_xor_128B
    UINT64_C(528482328),	// V6_vgtw
    UINT64_C(528482328),	// V6_vgtw_128B
    UINT64_C(478158872),	// V6_vgtw_and
    UINT64_C(478158872),	// V6_vgtw_and_128B
    UINT64_C(478158936),	// V6_vgtw_or
    UINT64_C(478158936),	// V6_vgtw_or_128B
    UINT64_C(478159000),	// V6_vgtw_xor
    UINT64_C(478159000),	// V6_vgtw_xor_128B
    UINT64_C(503324800),	// V6_vhist
    UINT64_C(503455872),	// V6_vhistq
    UINT64_C(429924384),	// V6_vinsertwr
    UINT64_C(429924384),	// V6_vinsertwr_128B
    UINT64_C(452984864),	// V6_vlalignb
    UINT64_C(452984864),	// V6_vlalignb_128B
    UINT64_C(509616128),	// V6_vlalignbi
    UINT64_C(509616128),	// V6_vlalignbi_128B
    UINT64_C(427819072),	// V6_vlsrh
    UINT64_C(427819072),	// V6_vlsrh_128B
    UINT64_C(530579520),	// V6_vlsrhv
    UINT64_C(530579520),	// V6_vlsrhv_128B
    UINT64_C(427819040),	// V6_vlsrw
    UINT64_C(427819040),	// V6_vlsrw_128B
    UINT64_C(530579488),	// V6_vlsrwv
    UINT64_C(530579488),	// V6_vlsrwv_128B
    UINT64_C(452993056),	// V6_vlutvvb
    UINT64_C(452993056),	// V6_vlutvvb_128B
    UINT64_C(452993184),	// V6_vlutvvb_oracc
    UINT64_C(452993184),	// V6_vlutvvb_oracc_128B
    UINT64_C(452993216),	// V6_vlutvwh
    UINT64_C(452993216),	// V6_vlutvwh_128B
    UINT64_C(452993248),	// V6_vlutvwh_oracc
    UINT64_C(452993248),	// V6_vlutvwh_oracc_128B
    UINT64_C(520093920),	// V6_vmaxh
    UINT64_C(520093920),	// V6_vmaxh_128B
    UINT64_C(520093856),	// V6_vmaxub
    UINT64_C(520093856),	// V6_vmaxub_128B
    UINT64_C(520093888),	// V6_vmaxuh
    UINT64_C(520093888),	// V6_vmaxuh_128B
    UINT64_C(522190848),	// V6_vmaxw
    UINT64_C(522190848),	// V6_vmaxw_128B
    UINT64_C(520093792),	// V6_vminh
    UINT64_C(520093792),	// V6_vminh_128B
    UINT64_C(520093728),	// V6_vminub
    UINT64_C(520093728),	// V6_vminub_128B
    UINT64_C(520093760),	// V6_vminuh
    UINT64_C(520093760),	// V6_vminuh_128B
    UINT64_C(520093824),	// V6_vminw
    UINT64_C(520093824),	// V6_vminw_128B
    UINT64_C(421527744),	// V6_vmpabus
    UINT64_C(421527744),	// V6_vmpabus_128B
    UINT64_C(421535936),	// V6_vmpabus_acc
    UINT64_C(421535936),	// V6_vmpabus_acc_128B
    UINT64_C(471859296),	// V6_vmpabusv
    UINT64_C(471859296),	// V6_vmpabusv_128B
    UINT64_C(484442336),	// V6_vmpabuuv
    UINT64_C(484442336),	// V6_vmpabuuv_128B
    UINT64_C(421527776),	// V6_vmpahb
    UINT64_C(421527776),	// V6_vmpahb_128B
    UINT64_C(421535968),	// V6_vmpahb_acc
    UINT64_C(421535968),	// V6_vmpahb_acc_128B
    UINT64_C(421527712),	// V6_vmpybus
    UINT64_C(421527712),	// V6_vmpybus_128B
    UINT64_C(421535904),	// V6_vmpybus_acc
    UINT64_C(421535904),	// V6_vmpybus_acc_128B
    UINT64_C(469762240),	// V6_vmpybusv
    UINT64_C(469762240),	// V6_vmpybusv_128B
    UINT64_C(469770432),	// V6_vmpybusv_acc
    UINT64_C(469770432),	// V6_vmpybusv_acc_128B
    UINT64_C(469762176),	// V6_vmpybv
    UINT64_C(469762176),	// V6_vmpybv_128B
    UINT64_C(469770368),	// V6_vmpybv_acc
    UINT64_C(469770368),	// V6_vmpybv_acc_128B
    UINT64_C(534773920),	// V6_vmpyewuh
    UINT64_C(534773920),	// V6_vmpyewuh_128B
    UINT64_C(423624704),	// V6_vmpyh
    UINT64_C(423624704),	// V6_vmpyh_128B
    UINT64_C(423632896),	// V6_vmpyhsat_acc
    UINT64_C(423632896),	// V6_vmpyhsat_acc_128B
    UINT64_C(423624768),	// V6_vmpyhsrs
    UINT64_C(423624768),	// V6_vmpyhsrs_128B
    UINT64_C(423624736),	// V6_vmpyhss
    UINT64_C(423624736),	// V6_vmpyhss_128B
    UINT64_C(471859264),	// V6_vmpyhus
    UINT64_C(471859264),	// V6_vmpyhus_128B
    UINT64_C(471867424),	// V6_vmpyhus_acc
    UINT64_C(471867424),	// V6_vmpyhus_acc_128B
    UINT64_C(469762272),	// V6_vmpyhv
    UINT64_C(469762272),	// V6_vmpyhv_128B
    UINT64_C(469770464),	// V6_vmpyhv_acc
    UINT64_C(469770464),	// V6_vmpyhv_acc_128B
    UINT64_C(471859232),	// V6_vmpyhvsrs
    UINT64_C(471859232),	// V6_vmpyhvsrs_128B
    UINT64_C(526385152),	// V6_vmpyieoh
    UINT64_C(526385152),	// V6_vmpyieoh_128B
    UINT64_C(473964544),	// V6_vmpyiewh_acc
    UINT64_C(473964544),	// V6_vmpyiewh_acc_128B
    UINT64_C(532676608),	// V6_vmpyiewuh
    UINT64_C(532676608),	// V6_vmpyiewuh_128B
    UINT64_C(471867552),	// V6_vmpyiewuh_acc
    UINT64_C(471867552),	// V6_vmpyiewuh_acc_128B
    UINT64_C(471859328),	// V6_vmpyih
    UINT64_C(471859328),	// V6_vmpyih_128B
    UINT64_C(471867520),	// V6_vmpyih_acc
    UINT64_C(471867520),	// V6_vmpyih_acc_128B
    UINT64_C(425721856),	// V6_vmpyihb
    UINT64_C(425721856),	// V6_vmpyihb_128B
    UINT64_C(425730080),	// V6_vmpyihb_acc
    UINT64_C(425730080),	// V6_vmpyihb_acc_128B
    UINT64_C(532676640),	// V6_vmpyiowh
    UINT64_C(532676640),	// V6_vmpyiowh_128B
    UINT64_C(429916160),	// V6_vmpyiwb
    UINT64_C(429916160),	// V6_vmpyiwb_128B
    UINT64_C(423632960),	// V6_vmpyiwb_acc
    UINT64_C(423632960),	// V6_vmpyiwb_acc_128B
    UINT64_C(427819232),	// V6_vmpyiwh
    UINT64_C(427819232),	// V6_vmpyiwh_128B
    UINT64_C(423632992),	// V6_vmpyiwh_acc
    UINT64_C(423632992),	// V6_vmpyiwh_acc_128B
    UINT64_C(534773984),	// V6_vmpyowh
    UINT64_C(534773984),	// V6_vmpyowh_128B
    UINT64_C(524288000),	// V6_vmpyowh_rnd
    UINT64_C(524288000),	// V6_vmpyowh_rnd_128B
    UINT64_C(471867616),	// V6_vmpyowh_rnd_sacc
    UINT64_C(471867616),	// V6_vmpyowh_rnd_sacc_128B
    UINT64_C(471867584),	// V6_vmpyowh_sacc
    UINT64_C(471867584),	// V6_vmpyowh_sacc_128B
    UINT64_C(432013312),	// V6_vmpyub
    UINT64_C(432013312),	// V6_vmpyub_128B
    UINT64_C(427827200),	// V6_vmpyub_acc
    UINT64_C(427827200),	// V6_vmpyub_acc_128B
    UINT64_C(469762208),	// V6_vmpyubv
    UINT64_C(469762208),	// V6_vmpyubv_128B
    UINT64_C(469770400),	// V6_vmpyubv_acc
    UINT64_C(469770400),	// V6_vmpyubv_acc_128B
    UINT64_C(423624800),	// V6_vmpyuh
    UINT64_C(423624800),	// V6_vmpyuh_128B
    UINT64_C(423632928),	// V6_vmpyuh_acc
    UINT64_C(423632928),	// V6_vmpyuh_acc_128B
    UINT64_C(471859200),	// V6_vmpyuhv
    UINT64_C(471859200),	// V6_vmpyuhv_128B
    UINT64_C(471867392),	// V6_vmpyuhv_acc
    UINT64_C(471867392),	// V6_vmpyuhv_acc_128B
    UINT64_C(518004736),	// V6_vmux
    UINT64_C(518004736),	// V6_vmux_128B
    UINT64_C(484442144),	// V6_vnavgh
    UINT64_C(484442144),	// V6_vnavgh_128B
    UINT64_C(484442112),	// V6_vnavgub
    UINT64_C(484442112),	// V6_vnavgub_128B
    UINT64_C(484442176),	// V6_vnavgw
    UINT64_C(484442176),	// V6_vnavgw_128B
    UINT64_C(440401920),	// V6_vnccombine
    UINT64_C(440401920),	// V6_vnccombine_128B
    UINT64_C(438304768),	// V6_vncmov
    UINT64_C(438304768),	// V6_vncmov_128B
    UINT64_C(503513248),	// V6_vnormamth
    UINT64_C(503513248),	// V6_vnormamth_128B
    UINT64_C(503513216),	// V6_vnormamtw
    UINT64_C(503513216),	// V6_vnormamtw_128B
    UINT64_C(503316608),	// V6_vnot
    UINT64_C(503316608),	// V6_vnot_128B
    UINT64_C(471859392),	// V6_vor
    UINT64_C(471859392),	// V6_vor_128B
    UINT64_C(532676672),	// V6_vpackeb
    UINT64_C(532676672),	// V6_vpackeb_128B
    UINT64_C(532676704),	// V6_vpackeh
    UINT64_C(532676704),	// V6_vpackeh_128B
    UINT64_C(532676800),	// V6_vpackhb_sat
    UINT64_C(532676800),	// V6_vpackhb_sat_128B
    UINT64_C(532676768),	// V6_vpackhub_sat
    UINT64_C(532676768),	// V6_vpackhub_sat_128B
    UINT64_C(534773792),	// V6_vpackob
    UINT64_C(534773792),	// V6_vpackob_128B
    UINT64_C(534773824),	// V6_vpackoh
    UINT64_C(534773824),	// V6_vpackoh_128B
    UINT64_C(534773760),	// V6_vpackwh_sat
    UINT64_C(534773760),	// V6_vpackwh_sat_128B
    UINT64_C(532676832),	// V6_vpackwuh_sat
    UINT64_C(532676832),	// V6_vpackwuh_sat_128B
    UINT64_C(503447744),	// V6_vpopcounth
    UINT64_C(503447744),	// V6_vpopcounth_128B
    UINT64_C(522190944),	// V6_vrdelta
    UINT64_C(522190944),	// V6_vrdelta_128B
    UINT64_C(419430528),	// V6_vrmpybus
    UINT64_C(419430528),	// V6_vrmpybus_128B
    UINT64_C(419438752),	// V6_vrmpybus_acc
    UINT64_C(419438752),	// V6_vrmpybus_acc_128B
    UINT64_C(423624832),	// V6_vrmpybusi
    UINT64_C(423624832),	// V6_vrmpybusi_128B
    UINT64_C(423633024),	// V6_vrmpybusi_acc
    UINT64_C(423633024),	// V6_vrmpybusi_acc_128B
    UINT64_C(469762112),	// V6_vrmpybusv
    UINT64_C(469762112),	// V6_vrmpybusv_128B
    UINT64_C(469770304),	// V6_vrmpybusv_acc
    UINT64_C(469770304),	// V6_vrmpybusv_acc_128B
    UINT64_C(469762080),	// V6_vrmpybv
    UINT64_C(469762080),	// V6_vrmpybv_128B
    UINT64_C(469770272),	// V6_vrmpybv_acc
    UINT64_C(469770272),	// V6_vrmpybv_acc_128B
    UINT64_C(419430496),	// V6_vrmpyub
    UINT64_C(419430496),	// V6_vrmpyub_128B
    UINT64_C(419438720),	// V6_vrmpyub_acc
    UINT64_C(419438720),	// V6_vrmpyub_acc_128B
    UINT64_C(429916352),	// V6_vrmpyubi
    UINT64_C(429916352),	// V6_vrmpyubi_128B
    UINT64_C(425730240),	// V6_vrmpyubi_acc
    UINT64_C(425730240),	// V6_vrmpyubi_acc_128B
    UINT64_C(469762048),	// V6_vrmpyubv
    UINT64_C(469762048),	// V6_vrmpyubv_128B
    UINT64_C(469770240),	// V6_vrmpyubv_acc
    UINT64_C(469770240),	// V6_vrmpyubv_acc_128B
    UINT64_C(425721888),	// V6_vror
    UINT64_C(425721888),	// V6_vror_128B
    UINT64_C(526385344),	// V6_vroundhb
    UINT64_C(526385344),	// V6_vroundhb_128B
    UINT64_C(526385376),	// V6_vroundhub
    UINT64_C(526385376),	// V6_vroundhub_128B
    UINT64_C(526385280),	// V6_vroundwh
    UINT64_C(526385280),	// V6_vroundwh_128B
    UINT64_C(526385312),	// V6_vroundwuh
    UINT64_C(526385312),	// V6_vroundwuh_128B
    UINT64_C(423624896),	// V6_vrsadubi
    UINT64_C(423624896),	// V6_vrsadubi_128B
    UINT64_C(423633088),	// V6_vrsadubi_acc
    UINT64_C(423633088),	// V6_vrsadubi_acc_128B
    UINT64_C(526385216),	// V6_vsathub
    UINT64_C(526385216),	// V6_vsathub_128B
    UINT64_C(526385248),	// V6_vsatwh
    UINT64_C(526385248),	// V6_vsatwh_128B
    UINT64_C(503447648),	// V6_vsb
    UINT64_C(503447648),	// V6_vsb_128B
    UINT64_C(503447680),	// V6_vsh
    UINT64_C(503447680),	// V6_vsh_128B
    UINT64_C(524288096),	// V6_vshufeh
    UINT64_C(524288096),	// V6_vshufeh_128B
    UINT64_C(434118688),	// V6_vshuff
    UINT64_C(434118688),	// V6_vshuff_128B
    UINT64_C(503447552),	// V6_vshuffb
    UINT64_C(503447552),	// V6_vshuffb_128B
    UINT64_C(524288032),	// V6_vshuffeb
    UINT64_C(524288032),	// V6_vshuffeb_128B
    UINT64_C(503382240),	// V6_vshuffh
    UINT64_C(503382240),	// V6_vshuffh_128B
    UINT64_C(524288064),	// V6_vshuffob
    UINT64_C(524288064),	// V6_vshuffob_128B
    UINT64_C(452993120),	// V6_vshuffvdd
    UINT64_C(452993120),	// V6_vshuffvdd_128B
    UINT64_C(524288192),	// V6_vshufoeb
    UINT64_C(524288192),	// V6_vshufoeb_128B
    UINT64_C(524288160),	// V6_vshufoeh
    UINT64_C(524288160),	// V6_vshufoeh_128B
    UINT64_C(524288128),	// V6_vshufoh
    UINT64_C(524288128),	// V6_vshufoh_128B
    UINT64_C(473956512),	// V6_vsubb
    UINT64_C(473956512),	// V6_vsubb_128B
    UINT64_C(478150752),	// V6_vsubb_dv
    UINT64_C(478150752),	// V6_vsubb_dv_128B
    UINT64_C(503455776),	// V6_vsubbnq
    UINT64_C(503455776),	// V6_vsubbnq_128B
    UINT64_C(503390400),	// V6_vsubbq
    UINT64_C(503390400),	// V6_vsubbq_128B
    UINT64_C(473956544),	// V6_vsubh
    UINT64_C(473956544),	// V6_vsubh_128B
    UINT64_C(478150784),	// V6_vsubh_dv
    UINT64_C(478150784),	// V6_vsubh_dv_128B
    UINT64_C(503455808),	// V6_vsubhnq
    UINT64_C(503455808),	// V6_vsubhnq_128B
    UINT64_C(503390432),	// V6_vsubhq
    UINT64_C(503390432),	// V6_vsubhq_128B
    UINT64_C(476053568),	// V6_vsubhsat
    UINT64_C(476053568),	// V6_vsubhsat_128B
    UINT64_C(480247808),	// V6_vsubhsat_dv
    UINT64_C(480247808),	// V6_vsubhsat_dv_128B
    UINT64_C(480248032),	// V6_vsubhw
    UINT64_C(480248032),	// V6_vsubhw_128B
    UINT64_C(480247968),	// V6_vsububh
    UINT64_C(480247968),	// V6_vsububh_128B
    UINT64_C(476053504),	// V6_vsububsat
    UINT64_C(476053504),	// V6_vsububsat_128B
    UINT64_C(478150848),	// V6_vsububsat_dv
    UINT64_C(478150848),	// V6_vsububsat_dv_128B
    UINT64_C(476053536),	// V6_vsubuhsat
    UINT64_C(476053536),	// V6_vsubuhsat_128B
    UINT64_C(478150880),	// V6_vsubuhsat_dv
    UINT64_C(478150880),	// V6_vsubuhsat_dv_128B
    UINT64_C(480248000),	// V6_vsubuhw
    UINT64_C(480248000),	// V6_vsubuhw_128B
    UINT64_C(473956576),	// V6_vsubw
    UINT64_C(473956576),	// V6_vsubw_128B
    UINT64_C(478150816),	// V6_vsubw_dv
    UINT64_C(478150816),	// V6_vsubw_dv_128B
    UINT64_C(503455840),	// V6_vsubwnq
    UINT64_C(503455840),	// V6_vsubwnq_128B
    UINT64_C(503455744),	// V6_vsubwq
    UINT64_C(503455744),	// V6_vsubwq_128B
    UINT64_C(476053600),	// V6_vsubwsat
    UINT64_C(476053600),	// V6_vsubwsat_128B
    UINT64_C(480247840),	// V6_vsubwsat_dv
    UINT64_C(480247840),	// V6_vsubwsat_dv_128B
    UINT64_C(513810432),	// V6_vswap
    UINT64_C(513810432),	// V6_vswap_128B
    UINT64_C(419430400),	// V6_vtmpyb
    UINT64_C(419430400),	// V6_vtmpyb_128B
    UINT64_C(419438592),	// V6_vtmpyb_acc
    UINT64_C(419438592),	// V6_vtmpyb_acc_128B
    UINT64_C(419430432),	// V6_vtmpybus
    UINT64_C(419430432),	// V6_vtmpybus_128B
    UINT64_C(419438624),	// V6_vtmpybus_acc
    UINT64_C(419438624),	// V6_vtmpybus_acc_128B
    UINT64_C(429916288),	// V6_vtmpyhb
    UINT64_C(429916288),	// V6_vtmpyhb_128B
    UINT64_C(419438656),	// V6_vtmpyhb_acc
    UINT64_C(419438656),	// V6_vtmpyhb_acc_128B
    UINT64_C(503382080),	// V6_vunpackb
    UINT64_C(503382080),	// V6_vunpackb_128B
    UINT64_C(503382112),	// V6_vunpackh
    UINT64_C(503382112),	// V6_vunpackh_128B
    UINT64_C(503324672),	// V6_vunpackob
    UINT64_C(503324672),	// V6_vunpackob_128B
    UINT64_C(503324704),	// V6_vunpackoh
    UINT64_C(503324704),	// V6_vunpackoh_128B
    UINT64_C(503382016),	// V6_vunpackub
    UINT64_C(503382016),	// V6_vunpackub_128B
    UINT64_C(503382048),	// V6_vunpackuh
    UINT64_C(503382048),	// V6_vunpackuh_128B
    UINT64_C(471859424),	// V6_vxor
    UINT64_C(471859424),	// V6_vxor_128B
    UINT64_C(503447584),	// V6_vzb
    UINT64_C(503447584),	// V6_vzb_128B
    UINT64_C(503447616),	// V6_vzh
    UINT64_C(503447616),	// V6_vzh_128B
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(0),
    UINT64_C(2818572288),	// Y2_barrier
    UINT64_C(2684354560),	// Y2_dccleana
    UINT64_C(2688548864),	// Y2_dccleaninva
    UINT64_C(2483027968),	// Y2_dcfetchbo
    UINT64_C(2686451712),	// Y2_dcinva
    UINT64_C(2696937472),	// Y2_dczeroa
    UINT64_C(1455423488),	// Y2_icinva
    UINT64_C(1472200706),	// Y2_isync
    UINT64_C(2822766592),	// Y2_syncht
    UINT64_C(2785017856),	// Y4_l2fetch
    UINT64_C(1648361472),	// Y4_trace
    UINT64_C(2793406464),	// Y5_l2fetch
    UINT64_C(2820673536),	// Y5_l2gclean
    UINT64_C(2820675584),	// Y5_l2gcleaninv
    UINT64_C(2820671488),	// Y5_l2gunlock
    UINT64_C(2699042816),	// Y5_l2locka
    UINT64_C(2791309312),	// Y5_l2unlocka
    UINT64_C(2797600768),	// Y6_l2gcleaninvpa
    UINT64_C(2795503616),	// Y6_l2gcleanpa
    UINT64_C(3581935616),	// dep_A2_addsat
    UINT64_C(3581935744),	// dep_A2_subsat
    UINT64_C(3556769792),	// dep_S2_packhl
    UINT64_C(0)
  };
  const unsigned opcode = MI.getOpcode();
  uint64_t Value = InstBits[opcode];
  uint64_t op = 0;
  (void)op;  // suppress warning
  switch (opcode) {
    case Hexagon::A2_addsp:
    case Hexagon::A2_nop:
    case Hexagon::A2_not:
    case Hexagon::A2_tfrp:
    case Hexagon::A2_tfrpf:
    case Hexagon::A2_tfrpfnew:
    case Hexagon::A2_tfrpi:
    case Hexagon::A2_tfrpt:
    case Hexagon::A2_tfrptnew:
    case Hexagon::A4_boundscheck:
    case Hexagon::ARGEXTEND:
    case Hexagon::C2_pxfer_map:
    case Hexagon::CONST32:
    case Hexagon::CONST32_Float_Real:
    case Hexagon::CONST32_Int_Real:
    case Hexagon::CONST64_Float_Real:
    case Hexagon::CONST64_Int_Real:
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
    case Hexagon::FCONST32_nsdata:
    case Hexagon::HEXAGON_V6_vd0_pseudo:
    case Hexagon::HEXAGON_V6_vd0_pseudo_128B:
    case Hexagon::HI_GOT:
    case Hexagon::HI_GOTREL:
    case Hexagon::HI_PIC:
    case Hexagon::L2_deallocframe:
    case Hexagon::L4_return:
    case Hexagon::LO_GOT:
    case Hexagon::LO_GOTREL:
    case Hexagon::LO_PIC:
    case Hexagon::M2_mpysmi:
    case Hexagon::M2_mpyui:
    case Hexagon::M2_vrcmpys_acc_s1:
    case Hexagon::M2_vrcmpys_s1:
    case Hexagon::M2_vrcmpys_s1rp:
    case Hexagon::S2_asr_i_p_rnd_goodsyntax:
    case Hexagon::S2_asr_i_r_rnd_goodsyntax:
    case Hexagon::S5_asrhub_rnd_sat_goodsyntax:
    case Hexagon::S5_vasrhrnd_goodsyntax:
    case Hexagon::TFRI64_V2_ext:
    case Hexagon::TFRI64_V4:
    case Hexagon::V4_SL2_deallocframe:
    case Hexagon::V4_SL2_jumpr31:
    case Hexagon::V4_SL2_jumpr31_f:
    case Hexagon::V4_SL2_jumpr31_fnew:
    case Hexagon::V4_SL2_jumpr31_t:
    case Hexagon::V4_SL2_jumpr31_tnew:
    case Hexagon::V4_SL2_return:
    case Hexagon::V4_SL2_return_f:
    case Hexagon::V4_SL2_return_fnew:
    case Hexagon::V4_SL2_return_t:
    case Hexagon::V4_SL2_return_tnew:
    case Hexagon::V6_vhist:
    case Hexagon::Y2_barrier:
    case Hexagon::Y2_isync:
    case Hexagon::Y2_syncht:
    case Hexagon::Y5_l2gclean:
    case Hexagon::Y5_l2gcleaninv:
    case Hexagon::Y5_l2gunlock: {
      break;
    }
    case Hexagon::C2_all8:
    case Hexagon::C2_any8:
    case Hexagon::C2_not: {
      // op: Pd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: Ps
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 16;
      break;
    }
    case Hexagon::C2_xor:
    case Hexagon::C4_fastcorner9:
    case Hexagon::C4_fastcorner9_not: {
      // op: Pd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: Ps
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 16;
      // op: Pt
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 8;
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
      // op: Pd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: Ps
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 16;
      // op: Pt
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 8;
      // op: Pu
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 6;
      break;
    }
    case Hexagon::C2_and:
    case Hexagon::C2_andn:
    case Hexagon::C2_or:
    case Hexagon::C2_orn: {
      // op: Pd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: Ps
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 8;
      // op: Pt
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 16;
      break;
    }
    case Hexagon::C2_tfrrp: {
      // op: Pd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::A4_cmpbeqi:
    case Hexagon::A4_cmpbgti:
    case Hexagon::A4_cmpbgtui:
    case Hexagon::A4_cmpheqi:
    case Hexagon::A4_cmphgti:
    case Hexagon::A4_cmphgtui: {
      // op: Pd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Imm
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(255)) << 5;
      break;
    }
    case Hexagon::A4_cmpbeq:
    case Hexagon::A4_cmpbgt:
    case Hexagon::A4_cmpbgtu:
    case Hexagon::A4_cmpheq:
    case Hexagon::A4_cmphgt:
    case Hexagon::A4_cmphgtu:
    case Hexagon::A4_tlbmatch:
    case Hexagon::C2_bitsclr:
    case Hexagon::C2_bitsset:
    case Hexagon::C2_cmpeqp:
    case Hexagon::C2_cmpgtp:
    case Hexagon::C2_cmpgtup:
    case Hexagon::C4_nbitsclr:
    case Hexagon::C4_nbitsset:
    case Hexagon::S2_storew_locked:
    case Hexagon::S2_tstbit_r:
    case Hexagon::S4_ntstbit_r:
    case Hexagon::S4_stored_locked: {
      // op: Pd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::F2_sfclass:
    case Hexagon::S2_tstbit_i:
    case Hexagon::S4_ntstbit_i: {
      // op: Pd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: u5
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::C2_bitsclri:
    case Hexagon::C4_nbitsclri: {
      // op: Pd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: u6
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(63)) << 8;
      break;
    }
    case Hexagon::A4_vcmpbgtui:
    case Hexagon::A4_vcmphgtui:
    case Hexagon::A4_vcmpwgtui: {
      // op: Pd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: Rss
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Imm
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(127)) << 5;
      break;
    }
    case Hexagon::A4_vcmpbeqi:
    case Hexagon::A4_vcmpbgti:
    case Hexagon::A4_vcmpheqi:
    case Hexagon::A4_vcmphgti:
    case Hexagon::A4_vcmpweqi:
    case Hexagon::A4_vcmpwgti: {
      // op: Pd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: Rss
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Imm
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(255)) << 5;
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
    case Hexagon::A4_vcmpbgt: {
      // op: Pd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: Rss
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rtt
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::F2_dfclass: {
      // op: Pd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: Rss
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: u5
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 5;
      break;
    }
    case Hexagon::J2_callf:
    case Hexagon::J2_callt: {
      // op: Pu
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 8;
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(98304)) << 7;
      Value |= (op & UINT64_C(31744)) << 6;
      Value |= (op & UINT64_C(512)) << 4;
      Value |= (op & UINT64_C(508)) >> 1;
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
    case Hexagon::C2_ccombinewf:
    case Hexagon::C2_ccombinewnewf:
    case Hexagon::C2_ccombinewnewt:
    case Hexagon::C2_ccombinewt: {
      // op: Pu
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 5;
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      break;
    }
    case Hexagon::A2_psubf:
    case Hexagon::A2_psubfnew:
    case Hexagon::A2_psubt:
    case Hexagon::A2_psubtnew: {
      // op: Pu
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 5;
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
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
      // op: Pv
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 5;
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Ru
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: u2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(2)) << 12;
      Value |= (op & UINT64_C(1)) << 7;
      // op: Nt
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= op & UINT64_C(7);
      break;
    }
    case Hexagon::S4_pstorerbf_rr:
    case Hexagon::S4_pstorerbfnew_rr:
    case Hexagon::S4_pstorerbt_rr:
    case Hexagon::S4_pstorerbtnew_rr:
    case Hexagon::S4_pstorerdf_rr:
    case Hexagon::S4_pstorerdfnew_rr:
    case Hexagon::S4_pstorerdt_rr:
    case Hexagon::S4_pstorerdtnew_rr:
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
      // op: Pv
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 5;
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Ru
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: u2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(2)) << 12;
      Value |= (op & UINT64_C(1)) << 7;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= op & UINT64_C(31);
      break;
    }
    case Hexagon::S4_storeirhf_io:
    case Hexagon::S4_storeirhfnew_io:
    case Hexagon::S4_storeirht_io:
    case Hexagon::S4_storeirhtnew_io: {
      // op: Pv
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 5;
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: S6
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(32)) << 8;
      Value |= op & UINT64_C(31);
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(126)) << 6;
      break;
    }
    case Hexagon::S4_storeirif_io:
    case Hexagon::S4_storeirifnew_io:
    case Hexagon::S4_storeirit_io:
    case Hexagon::S4_storeiritnew_io: {
      // op: Pv
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 5;
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: S6
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(32)) << 8;
      Value |= op & UINT64_C(31);
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(252)) << 5;
      break;
    }
    case Hexagon::S4_storeirbf_io:
    case Hexagon::S4_storeirbfnew_io:
    case Hexagon::S4_storeirbt_io:
    case Hexagon::S4_storeirbtnew_io: {
      // op: Pv
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 5;
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: S6
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(32)) << 8;
      Value |= op & UINT64_C(31);
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(63)) << 7;
      break;
    }
    case Hexagon::J4_jumpseti: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 16;
      // op: U6
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(63)) << 8;
      // op: r9_2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(1536)) << 11;
      Value |= (op & UINT64_C(508)) >> 1;
      break;
    }
    case Hexagon::J4_jumpsetr: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 8;
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 16;
      // op: r9_2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(1536)) << 11;
      Value |= (op & UINT64_C(508)) >> 1;
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
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: u8
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(224)) << 16;
      Value |= (op & UINT64_C(16)) << 9;
      Value |= (op & UINT64_C(14)) << 4;
      Value |= (op & UINT64_C(1)) << 3;
      // op: U5
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S4_addaddi: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Ru
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: s6
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(48)) << 17;
      Value |= (op & UINT64_C(8)) << 10;
      Value |= (op & UINT64_C(7)) << 5;
      break;
    }
    case Hexagon::S4_subaddi: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: s6
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(48)) << 17;
      Value |= (op & UINT64_C(8)) << 10;
      Value |= (op & UINT64_C(7)) << 5;
      // op: Ru
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= op & UINT64_C(31);
      break;
    }
    case Hexagon::M4_mpyri_addi: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: u6
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(48)) << 17;
      Value |= (op & UINT64_C(8)) << 10;
      Value |= (op & UINT64_C(7)) << 5;
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: U6
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(32)) << 18;
      Value |= op & UINT64_C(31);
      break;
    }
    case Hexagon::V4_SA1_clrf:
    case Hexagon::V4_SA1_clrfnew:
    case Hexagon::V4_SA1_clrt:
    case Hexagon::V4_SA1_clrtnew:
    case Hexagon::V4_SA1_setin1: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(15);
      break;
    }
    case Hexagon::V4_SA1_and1:
    case Hexagon::V4_SA1_dec:
    case Hexagon::V4_SA1_inc:
    case Hexagon::V4_SA1_sxtb:
    case Hexagon::V4_SA1_sxth:
    case Hexagon::V4_SA1_tfr:
    case Hexagon::V4_SA1_zxtb:
    case Hexagon::V4_SA1_zxth: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(15);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 4;
      break;
    }
    case Hexagon::V4_SL2_loadrb_io: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(15);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 4;
      // op: u3_0
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 8;
      break;
    }
    case Hexagon::V4_SL2_loadrh_io:
    case Hexagon::V4_SL2_loadruh_io: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(15);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 4;
      // op: u3_1
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(14)) << 7;
      break;
    }
    case Hexagon::V4_SL1_loadrub_io: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(15);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 4;
      // op: u4_0
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 8;
      break;
    }
    case Hexagon::V4_SL1_loadri_io: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(15);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 4;
      // op: u4_2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(60)) << 6;
      break;
    }
    case Hexagon::V4_SL2_loadri_sp: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(15);
      // op: u5_2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(124)) << 2;
      break;
    }
    case Hexagon::V4_SA1_seti: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(15);
      // op: u6
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(63)) << 4;
      break;
    }
    case Hexagon::V4_SA1_addsp: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(15);
      // op: u6_2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(252)) << 2;
      break;
    }
    case Hexagon::F2_sfinvsqrta: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Pe
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 5;
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::F2_sfrecipa: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Pe
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 5;
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::C2_tfrpr: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Ps
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 16;
      break;
    }
    case Hexagon::C2_vitpack: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Ps
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 16;
      // op: Pt
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 8;
      break;
    }
    case Hexagon::C2_mask: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Pt
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 8;
      break;
    }
    case Hexagon::A2_paddif:
    case Hexagon::A2_paddifnew:
    case Hexagon::A2_paddit:
    case Hexagon::A2_padditnew: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Pu
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 21;
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: s8
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(255)) << 5;
      break;
    }
    case Hexagon::C2_cmoveif:
    case Hexagon::C2_cmoveit:
    case Hexagon::C2_cmovenewif:
    case Hexagon::C2_cmovenewit: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Pu
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 21;
      // op: s12
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(3840)) << 8;
      Value |= (op & UINT64_C(255)) << 5;
      break;
    }
    case Hexagon::C2_muxri: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Pu
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 21;
      // op: s8
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(255)) << 5;
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::C2_muxir: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Pu
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 21;
      // op: s8
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(255)) << 5;
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::C2_muxii: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Pu
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 23;
      // op: s8
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(255)) << 5;
      // op: S8
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(254)) << 15;
      Value |= (op & UINT64_C(1)) << 13;
      break;
    }
    case Hexagon::C2_mux:
    case Hexagon::C2_vmux: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Pu
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 5;
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
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
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Pu
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 8;
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::A2_aslh:
    case Hexagon::A2_asrh:
    case Hexagon::A2_sxtb:
    case Hexagon::A2_sxth:
    case Hexagon::A2_zxtb:
    case Hexagon::A2_zxth:
    case Hexagon::F2_conv_sf2uw:
    case Hexagon::F2_conv_sf2uw_chop:
    case Hexagon::F2_conv_sf2w:
    case Hexagon::F2_conv_sf2w_chop:
    case Hexagon::F2_conv_uw2sf:
    case Hexagon::F2_conv_w2sf:
    case Hexagon::F2_sffixupr: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::A4_bitsplit:
    case Hexagon::A4_modwrapu:
    case Hexagon::F2_sfadd:
    case Hexagon::F2_sffixupd:
    case Hexagon::F2_sffixupn:
    case Hexagon::F2_sfmax:
    case Hexagon::F2_sfmin:
    case Hexagon::F2_sfmpy:
    case Hexagon::F2_sfsub:
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
    case Hexagon::M2_mpyu_hh_s0:
    case Hexagon::M2_mpyu_hh_s1:
    case Hexagon::M2_mpyu_hl_s0:
    case Hexagon::M2_mpyu_hl_s1:
    case Hexagon::M2_mpyu_lh_s0:
    case Hexagon::M2_mpyu_lh_s1:
    case Hexagon::M2_mpyu_ll_s0:
    case Hexagon::M2_mpyu_ll_s1:
    case Hexagon::S2_clrbit_r:
    case Hexagon::S2_parityp:
    case Hexagon::S2_setbit_r:
    case Hexagon::S2_togglebit_r:
    case Hexagon::S4_parity:
    case Hexagon::dep_A2_addsat:
    case Hexagon::dep_S2_packhl: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S2_extractu_rp:
    case Hexagon::S4_extract_rp: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rtt
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::A2_andir:
    case Hexagon::A2_orir: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: s10
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(512)) << 12;
      Value |= (op & UINT64_C(511)) << 5;
      break;
    }
    case Hexagon::A2_addi: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: s16
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(65024)) << 12;
      Value |= (op & UINT64_C(511)) << 5;
      break;
    }
    case Hexagon::A4_rcmpeqi:
    case Hexagon::A4_rcmpneqi: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: s8
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(255)) << 5;
      break;
    }
    case Hexagon::S2_clrbit_i:
    case Hexagon::S2_setbit_i:
    case Hexagon::S2_togglebit_i: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: u5
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::M2_mpysin:
    case Hexagon::M2_mpysip: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: u8
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(255)) << 5;
      break;
    }
    case Hexagon::dep_A2_subsat: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::A2_minp:
    case Hexagon::A2_minup: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::A2_maxp:
    case Hexagon::A2_maxup: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::F2_conv_d2sf:
    case Hexagon::F2_conv_df2sf:
    case Hexagon::F2_conv_df2uw:
    case Hexagon::F2_conv_df2uw_chop:
    case Hexagon::F2_conv_df2w:
    case Hexagon::F2_conv_df2w_chop:
    case Hexagon::F2_conv_ud2sf:
    case Hexagon::S5_popcountp: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rss
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::M4_cmpyi_wh:
    case Hexagon::M4_cmpyi_whc:
    case Hexagon::M4_cmpyr_wh:
    case Hexagon::M4_cmpyr_whc:
    case Hexagon::S2_asr_r_svw_trun: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rss
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S5_asrhub_rnd_sat:
    case Hexagon::S5_asrhub_sat: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rss
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: u4
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 8;
      break;
    }
    case Hexagon::A2_max:
    case Hexagon::A2_maxu: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
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
    case Hexagon::A2_min:
    case Hexagon::A2_minu:
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
    case Hexagon::A2_subh_l16_sat_ll: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::S2_addasl_rrri: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: u3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 5;
      break;
    }
    case Hexagon::A2_subri: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: s10
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(512)) << 12;
      Value |= (op & UINT64_C(511)) << 5;
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::A2_tfrsi: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: s16
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(49152)) << 8;
      Value |= (op & UINT64_C(15872)) << 7;
      Value |= (op & UINT64_C(511)) << 5;
      break;
    }
    case Hexagon::S4_lsli: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: s6
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(62)) << 15;
      Value |= (op & UINT64_C(1)) << 5;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::M4_mpyrr_addi: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: u6
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(48)) << 17;
      Value |= (op & UINT64_C(8)) << 10;
      Value |= (op & UINT64_C(7)) << 5;
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::C4_addipc: {
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: u6
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(63)) << 7;
      break;
    }
    case Hexagon::F2_conv_sf2d:
    case Hexagon::F2_conv_sf2d_chop:
    case Hexagon::F2_conv_sf2df:
    case Hexagon::F2_conv_sf2ud:
    case Hexagon::F2_conv_sf2ud_chop:
    case Hexagon::F2_conv_uw2df:
    case Hexagon::F2_conv_w2df: {
      // op: Rdd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
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
    case Hexagon::M5_vmpybuu: {
      // op: Rdd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::A4_combineri: {
      // op: Rdd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: s8
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(255)) << 5;
      break;
    }
    case Hexagon::A4_combineir: {
      // op: Rdd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: s8
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(255)) << 5;
      break;
    }
    case Hexagon::F2_conv_d2df:
    case Hexagon::F2_conv_df2d:
    case Hexagon::F2_conv_df2d_chop:
    case Hexagon::F2_conv_df2ud:
    case Hexagon::F2_conv_df2ud_chop:
    case Hexagon::F2_conv_ud2df: {
      // op: Rdd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rss
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::S4_vrcrotate: {
      // op: Rdd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rss
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: u2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(2)) << 12;
      Value |= (op & UINT64_C(1)) << 5;
      break;
    }
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
    case Hexagon::M5_vrmpybuu: {
      // op: Rdd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rss
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rtt
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S2_vsplicerb: {
      // op: Rdd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rss
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rtt
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: Pu
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 5;
      break;
    }
    case Hexagon::S2_vspliceib: {
      // op: Rdd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rss
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rtt
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: u3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 5;
      break;
    }
    case Hexagon::S5_vasrhrnd: {
      // op: Rdd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rss
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: u4
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 8;
      break;
    }
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
    case Hexagon::A2_vsubws: {
      // op: Rdd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rss
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: Rtt
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::S2_valignrb: {
      // op: Rdd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rss
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: Rtt
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Pu
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 5;
      break;
    }
    case Hexagon::S2_valignib: {
      // op: Rdd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rss
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: Rtt
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: u3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 5;
      break;
    }
    case Hexagon::M2_vabsdiffh:
    case Hexagon::M2_vabsdiffw: {
      // op: Rdd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rss
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rtt
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::A2_vraddub_acc:
    case Hexagon::A2_vrsadub_acc:
    case Hexagon::M2_vrcmaci_s0:
    case Hexagon::M2_vrcmaci_s0c:
    case Hexagon::M2_vrcmacr_s0:
    case Hexagon::M2_vrcmacr_s0c:
    case Hexagon::M2_vrmac_s0:
    case Hexagon::M5_vrmacbsu:
    case Hexagon::M5_vrmacbuu: {
      // op: Rdd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rss
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rtt
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::A4_addp_c:
    case Hexagon::A4_subp_c: {
      // op: Rdd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rss
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rtt
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: Pu
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 5;
      break;
    }
    case Hexagon::A2_combineii: {
      // op: Rdd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: s8
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(255)) << 5;
      // op: S8
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(254)) << 15;
      Value |= (op & UINT64_C(1)) << 13;
      break;
    }
    case Hexagon::A4_combineii: {
      // op: Rdd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: s8
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(255)) << 5;
      // op: U6
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(62)) << 15;
      Value |= (op & UINT64_C(1)) << 13;
      break;
    }
    case Hexagon::V4_SA1_combinerz:
    case Hexagon::V4_SA1_combinezr: {
      // op: Rdd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(7);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 4;
      break;
    }
    case Hexagon::V4_SA1_combine0i:
    case Hexagon::V4_SA1_combine1i:
    case Hexagon::V4_SA1_combine2i:
    case Hexagon::V4_SA1_combine3i: {
      // op: Rdd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(7);
      // op: u2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 5;
      break;
    }
    case Hexagon::V4_SL2_loadrd_sp: {
      // op: Rdd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(7);
      // op: u5_3
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= op & UINT64_C(248);
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
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 16;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 8;
      // op: r9_2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(1536)) << 11;
      Value |= (op & UINT64_C(508)) >> 1;
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
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 16;
      // op: U5
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: r9_2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(1536)) << 11;
      Value |= (op & UINT64_C(508)) >> 1;
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
    case Hexagon::J4_cmpgtn1_tp1_jump_t:
    case Hexagon::J4_tstbit0_fp0_jump_nt:
    case Hexagon::J4_tstbit0_fp0_jump_t:
    case Hexagon::J4_tstbit0_fp1_jump_nt:
    case Hexagon::J4_tstbit0_fp1_jump_t:
    case Hexagon::J4_tstbit0_tp0_jump_nt:
    case Hexagon::J4_tstbit0_tp0_jump_t:
    case Hexagon::J4_tstbit0_tp1_jump_nt:
    case Hexagon::J4_tstbit0_tp1_jump_t: {
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 16;
      // op: r9_2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(1536)) << 11;
      Value |= (op & UINT64_C(508)) >> 1;
      break;
    }
    case Hexagon::V4_SA1_cmpeqi: {
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 4;
      // op: u2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= op & UINT64_C(3);
      break;
    }
    case Hexagon::V4_SS2_storeh_io: {
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 4;
      // op: u3_1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(14)) << 7;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= op & UINT64_C(15);
      break;
    }
    case Hexagon::V4_SS1_storeb_io: {
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 4;
      // op: u4_0
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 8;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= op & UINT64_C(15);
      break;
    }
    case Hexagon::V4_SS2_storebi0:
    case Hexagon::V4_SS2_storebi1: {
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 4;
      // op: u4_0
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= op & UINT64_C(15);
      break;
    }
    case Hexagon::V4_SS1_storew_io: {
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 4;
      // op: u4_2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(60)) << 6;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= op & UINT64_C(15);
      break;
    }
    case Hexagon::V4_SS2_storewi0:
    case Hexagon::V4_SS2_storewi1: {
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 4;
      // op: u4_2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(60)) >> 2;
      break;
    }
    case Hexagon::CALLRv3nr:
    case Hexagon::J2_callr:
    case Hexagon::J4_hintjumpr:
    case Hexagon::Y2_dccleana:
    case Hexagon::Y2_dccleaninva:
    case Hexagon::Y2_dcinva:
    case Hexagon::Y2_dczeroa:
    case Hexagon::Y2_icinva:
    case Hexagon::Y4_trace: {
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::Y4_l2fetch:
    case Hexagon::Y5_l2fetch: {
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S4_storerbnew_rr:
    case Hexagon::S4_storerhnew_rr:
    case Hexagon::S4_storerinew_rr: {
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Ru
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: u2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(2)) << 12;
      Value |= (op & UINT64_C(1)) << 7;
      // op: Nt
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= op & UINT64_C(7);
      break;
    }
    case Hexagon::S4_storerb_rr:
    case Hexagon::S4_storerd_rr:
    case Hexagon::S4_storerf_rr:
    case Hexagon::S4_storerh_rr:
    case Hexagon::S4_storeri_rr: {
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Ru
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: u2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(2)) << 12;
      Value |= (op & UINT64_C(1)) << 7;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= op & UINT64_C(31);
      break;
    }
    case Hexagon::S4_storeirh_io: {
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: S8
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(128)) << 6;
      Value |= op & UINT64_C(127);
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(126)) << 6;
      break;
    }
    case Hexagon::S4_storeiri_io: {
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: S8
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(128)) << 6;
      Value |= op & UINT64_C(127);
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(252)) << 5;
      break;
    }
    case Hexagon::S4_storeirb_io: {
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: S8
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(128)) << 6;
      Value |= op & UINT64_C(127);
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(63)) << 7;
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
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: r13_2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(16384)) << 7;
      Value |= op & UINT64_C(8192);
      Value |= (op & UINT64_C(8188)) >> 1;
      break;
    }
    case Hexagon::Y2_dcfetchbo: {
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: u11_3
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(16376)) >> 3;
      break;
    }
    case Hexagon::J2_callrf:
    case Hexagon::J2_callrt: {
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Pu
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 8;
      break;
    }
    case Hexagon::S2_cl0:
    case Hexagon::S2_cl0p:
    case Hexagon::S2_cl1:
    case Hexagon::S2_cl1p:
    case Hexagon::S2_clb:
    case Hexagon::S2_clbnorm:
    case Hexagon::S2_clbp:
    case Hexagon::S2_ct0:
    case Hexagon::S2_ct0p:
    case Hexagon::S2_ct1:
    case Hexagon::S2_ct1p:
    case Hexagon::S4_clbpnorm: {
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      break;
    }
    case Hexagon::S4_clbaddi:
    case Hexagon::S4_clbpaddi: {
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: s6
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(63)) << 8;
      break;
    }
    case Hexagon::C2_cmpeq:
    case Hexagon::C2_cmpgt:
    case Hexagon::C2_cmpgtu:
    case Hexagon::C4_cmplte:
    case Hexagon::C4_cmplteu:
    case Hexagon::C4_cmpneq: {
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: Pd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(3);
      break;
    }
    case Hexagon::A2_add:
    case Hexagon::A2_addp:
    case Hexagon::A2_addpsat:
    case Hexagon::A2_addsat:
    case Hexagon::A2_addsph:
    case Hexagon::A2_addspl:
    case Hexagon::A2_and:
    case Hexagon::A2_andp:
    case Hexagon::A2_combinew:
    case Hexagon::A2_or:
    case Hexagon::A2_orp:
    case Hexagon::A2_svaddh:
    case Hexagon::A2_svaddhs:
    case Hexagon::A2_svadduhs:
    case Hexagon::A2_svavgh:
    case Hexagon::A2_svavghs:
    case Hexagon::A2_xor:
    case Hexagon::A2_xorp:
    case Hexagon::A4_rcmpeq:
    case Hexagon::A4_rcmpneq:
    case Hexagon::S2_packhl: {
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      break;
    }
    case Hexagon::A2_combine_hh:
    case Hexagon::A2_combine_hl:
    case Hexagon::A2_combine_lh:
    case Hexagon::A2_combine_ll:
    case Hexagon::A2_sub:
    case Hexagon::A2_subp:
    case Hexagon::A2_subsat:
    case Hexagon::A2_svnavgh:
    case Hexagon::A2_svsubh:
    case Hexagon::A2_svsubhs:
    case Hexagon::A2_svsubuhs:
    case Hexagon::A4_andn:
    case Hexagon::A4_andnp:
    case Hexagon::A4_orn:
    case Hexagon::A4_ornp: {
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
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
    case Hexagon::S2_brevp:
    case Hexagon::S2_deinterleave:
    case Hexagon::S2_interleave:
    case Hexagon::S2_vsathb_nopack:
    case Hexagon::S2_vsathub_nopack:
    case Hexagon::S2_vsatwh_nopack:
    case Hexagon::S2_vsatwuh_nopack: {
      // op: Rss
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rdd
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      break;
    }
    case Hexagon::S4_or_andix: {
      // op: Rx
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Ru
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: s10
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(512)) << 12;
      Value |= (op & UINT64_C(511)) << 5;
      break;
    }
    case Hexagon::A2_tfrih:
    case Hexagon::A2_tfril: {
      // op: Rx
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: u16
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(49152)) << 8;
      Value |= op & UINT64_C(16383);
      break;
    }
    case Hexagon::M4_mpyrr_addr: {
      // op: Rx
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: Ru
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::V4_SA1_addrx: {
      // op: Rx
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(15);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 4;
      break;
    }
    case Hexagon::V4_SA1_addi: {
      // op: Rx
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(15);
      // op: s7
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(127)) << 4;
      break;
    }
    case Hexagon::F2_sffma:
    case Hexagon::F2_sffma_lib:
    case Hexagon::F2_sffms:
    case Hexagon::F2_sffms_lib:
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
      // op: Rx
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::F2_sffma_sc: {
      // op: Rx
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: Pu
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 5;
      break;
    }
    case Hexagon::S4_or_andi:
    case Hexagon::S4_or_ori: {
      // op: Rx
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: s10
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(512)) << 12;
      Value |= (op & UINT64_C(511)) << 5;
      break;
    }
    case Hexagon::S2_tableidxb:
    case Hexagon::S2_tableidxd:
    case Hexagon::S2_tableidxh:
    case Hexagon::S2_tableidxw: {
      // op: Rx
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: u4
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(8)) << 18;
      Value |= (op & UINT64_C(7)) << 5;
      // op: S6
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(63)) << 8;
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
    case Hexagon::S2_lsr_i_r_xacc: {
      // op: Rx
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: u5
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
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
      // op: Rxx
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: Rss
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Ru
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= op & UINT64_C(31);
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
      // op: Rxx
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
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
      // op: Rxx
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rss
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S4_vrcrotate_acc: {
      // op: Rxx
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rss
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: u2
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(2)) << 12;
      Value |= (op & UINT64_C(1)) << 5;
      break;
    }
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
    case Hexagon::M2_vrcmpys_acc_s1_h:
    case Hexagon::M2_vrcmpys_acc_s1_l:
    case Hexagon::M4_vrmpyeh_acc_s0:
    case Hexagon::M4_vrmpyeh_acc_s1:
    case Hexagon::M4_vrmpyoh_acc_s0:
    case Hexagon::M4_vrmpyoh_acc_s1:
    case Hexagon::M4_xor_xacc:
    case Hexagon::M5_vdmacbsu: {
      // op: Rxx
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rss
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Rtt
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
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
    case Hexagon::S2_lsr_i_p_xacc: {
      // op: Rxx
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rss
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: u6
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(63)) << 8;
      break;
    }
    case Hexagon::S2_storerbnew_pbr:
    case Hexagon::S2_storerbnew_pcr:
    case Hexagon::S2_storerhnew_pbr:
    case Hexagon::S2_storerhnew_pcr:
    case Hexagon::S2_storerinew_pbr:
    case Hexagon::S2_storerinew_pcr: {
      // op: Rz
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Mu
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(1)) << 13;
      // op: Nt
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 8;
      break;
    }
    case Hexagon::S2_storerb_pcr:
    case Hexagon::S2_storerd_pcr:
    case Hexagon::S2_storerf_pcr:
    case Hexagon::S2_storerh_pcr:
    case Hexagon::S2_storeri_pcr: {
      // op: Rz
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Mu
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(1)) << 13;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S2_storerb_pbr:
    case Hexagon::S2_storerd_pbr:
    case Hexagon::S2_storerf_pbr:
    case Hexagon::S2_storerh_pbr:
    case Hexagon::S2_storeri_pbr: {
      // op: Rz
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Mu
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(1)) << 13;
      // op: src
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S2_storerbnew_pci: {
      // op: Rz
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 3;
      // op: Mu
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(1)) << 13;
      // op: Nt
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 8;
      break;
    }
    case Hexagon::S2_storerb_pci: {
      // op: Rz
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 3;
      // op: Mu
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(1)) << 13;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S2_storerhnew_pci: {
      // op: Rz
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(30)) << 2;
      // op: Mu
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(1)) << 13;
      // op: Nt
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 8;
      break;
    }
    case Hexagon::S2_storerf_pci:
    case Hexagon::S2_storerh_pci: {
      // op: Rz
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(30)) << 2;
      // op: Mu
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(1)) << 13;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S2_storerinew_pci: {
      // op: Rz
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(60)) << 1;
      // op: Mu
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(1)) << 13;
      // op: Nt
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 8;
      break;
    }
    case Hexagon::S2_storeri_pci: {
      // op: Rz
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(60)) << 1;
      // op: Mu
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(1)) << 13;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S2_storerd_pci: {
      // op: Rz
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= op & UINT64_C(120);
      // op: Mu
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(1)) << 13;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S2_storeriabs:
    case Hexagon::S2_storerigp: {
      // op: addr
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(196608)) << 9;
      Value |= (op & UINT64_C(63488)) << 5;
      Value |= (op & UINT64_C(1024)) << 3;
      Value |= (op & UINT64_C(1020)) >> 2;
      // op: src
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S2_storerinewabs:
    case Hexagon::S2_storerinewgp: {
      // op: addr
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(196608)) << 9;
      Value |= (op & UINT64_C(63488)) << 5;
      Value |= (op & UINT64_C(1024)) << 3;
      Value |= (op & UINT64_C(1020)) >> 2;
      // op: src
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 8;
      break;
    }
    case Hexagon::S2_storerdabs:
    case Hexagon::S2_storerdgp: {
      // op: addr
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(393216)) << 8;
      Value |= (op & UINT64_C(126976)) << 4;
      Value |= (op & UINT64_C(2048)) << 2;
      Value |= (op & UINT64_C(2040)) >> 3;
      // op: src
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S2_storerbabs:
    case Hexagon::S2_storerbgp: {
      // op: addr
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(49152)) << 11;
      Value |= (op & UINT64_C(15872)) << 7;
      Value |= (op & UINT64_C(256)) << 5;
      Value |= op & UINT64_C(255);
      // op: src
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S2_storerbnewabs:
    case Hexagon::S2_storerbnewgp: {
      // op: addr
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(49152)) << 11;
      Value |= (op & UINT64_C(15872)) << 7;
      Value |= (op & UINT64_C(256)) << 5;
      Value |= op & UINT64_C(255);
      // op: src
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 8;
      break;
    }
    case Hexagon::S2_storerfabs:
    case Hexagon::S2_storerfgp:
    case Hexagon::S2_storerhabs:
    case Hexagon::S2_storerhgp: {
      // op: addr
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(98304)) << 10;
      Value |= (op & UINT64_C(31744)) << 6;
      Value |= (op & UINT64_C(512)) << 4;
      Value |= (op & UINT64_C(510)) >> 1;
      // op: src
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S2_storerhnewabs:
    case Hexagon::S2_storerhnewgp: {
      // op: addr
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(98304)) << 10;
      Value |= (op & UINT64_C(31744)) << 6;
      Value |= (op & UINT64_C(512)) << 4;
      Value |= (op & UINT64_C(510)) >> 1;
      // op: src
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 8;
      break;
    }
    case Hexagon::L4_add_memoph_io:
    case Hexagon::L4_and_memoph_io:
    case Hexagon::L4_iadd_memoph_io:
    case Hexagon::L4_iand_memoph_io:
    case Hexagon::L4_ior_memoph_io:
    case Hexagon::L4_isub_memoph_io:
    case Hexagon::L4_or_memoph_io:
    case Hexagon::L4_sub_memoph_io: {
      // op: base
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: delta
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(126)) << 6;
      break;
    }
    case Hexagon::L4_add_memopw_io:
    case Hexagon::L4_and_memopw_io:
    case Hexagon::L4_iadd_memopw_io:
    case Hexagon::L4_iand_memopw_io:
    case Hexagon::L4_ior_memopw_io:
    case Hexagon::L4_isub_memopw_io:
    case Hexagon::L4_or_memopw_io:
    case Hexagon::L4_sub_memopw_io: {
      // op: base
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: delta
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(252)) << 5;
      break;
    }
    case Hexagon::L4_add_memopb_io:
    case Hexagon::L4_and_memopb_io:
    case Hexagon::L4_iadd_memopb_io:
    case Hexagon::L4_iand_memopb_io:
    case Hexagon::L4_ior_memopb_io:
    case Hexagon::L4_isub_memopb_io:
    case Hexagon::L4_or_memopb_io:
    case Hexagon::L4_sub_memopb_io: {
      // op: base
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: delta
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(63)) << 7;
      break;
    }
    case Hexagon::CALLv3nr:
    case Hexagon::J2_call:
    case Hexagon::J2_jump:
    case Hexagon::J2_jump_ext:
    case Hexagon::J2_jump_noext:
    case Hexagon::RESTORE_DEALLOC_BEFORE_TAILCALL_V4:
    case Hexagon::RESTORE_DEALLOC_BEFORE_TAILCALL_V4_EXT:
    case Hexagon::RESTORE_DEALLOC_RET_JMP_V4:
    case Hexagon::RESTORE_DEALLOC_RET_JMP_V4_EXT:
    case Hexagon::SAVE_REGISTERS_CALL_V4:
    case Hexagon::SAVE_REGISTERS_CALL_V4_EXT: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(16744448)) << 1;
      Value |= (op & UINT64_C(32764)) >> 1;
      break;
    }
    case Hexagon::EH_RETURN_JMPR:
    case Hexagon::J2_jumpr:
    case Hexagon::JMPret: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::S4_storerb_ap:
    case Hexagon::S4_storerd_ap:
    case Hexagon::S4_storerf_ap:
    case Hexagon::S4_storerh_ap:
    case Hexagon::S4_storeri_ap: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: addr
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= op & UINT64_C(63);
      // op: src
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S4_storerbnew_ap:
    case Hexagon::S4_storerhnew_ap:
    case Hexagon::S4_storerinew_ap: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: addr
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= op & UINT64_C(63);
      // op: src
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 8;
      break;
    }
    case Hexagon::HI:
    case Hexagon::LO_H: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: imm_value
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3221225472)) >> 8;
      Value |= (op & UINT64_C(1073676288)) >> 16;
      break;
    }
    case Hexagon::HI_L:
    case Hexagon::LO: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: imm_value
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(49152)) << 8;
      Value |= op & UINT64_C(16383);
      break;
    }
    case Hexagon::M4_mpyri_addr_u2: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(192)) << 15;
      Value |= (op & UINT64_C(32)) << 8;
      Value |= (op & UINT64_C(28)) << 3;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::M4_mpyri_addr: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(48)) << 17;
      Value |= (op & UINT64_C(8)) << 10;
      Value |= (op & UINT64_C(7)) << 5;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::V6_pred_not:
    case Hexagon::V6_pred_not_128B: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 8;
      break;
    }
    case Hexagon::V6_pred_and:
    case Hexagon::V6_pred_and_128B:
    case Hexagon::V6_pred_and_n:
    case Hexagon::V6_pred_and_n_128B:
    case Hexagon::V6_pred_or:
    case Hexagon::V6_pred_or_128B:
    case Hexagon::V6_pred_or_n:
    case Hexagon::V6_pred_or_n_128B:
    case Hexagon::V6_pred_xor:
    case Hexagon::V6_pred_xor_128B: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 8;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 22;
      break;
    }
    case Hexagon::V6_pred_scalar2:
    case Hexagon::V6_pred_scalar2_128B:
    case Hexagon::Y5_l2locka: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::F2_dfcmpeq:
    case Hexagon::F2_dfcmpge:
    case Hexagon::F2_dfcmpgt:
    case Hexagon::F2_dfcmpuo:
    case Hexagon::F2_sfcmpeq:
    case Hexagon::F2_sfcmpge:
    case Hexagon::F2_sfcmpgt:
    case Hexagon::F2_sfcmpuo: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::C2_cmpgtui:
    case Hexagon::C4_cmplteui: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(511)) << 5;
      break;
    }
    case Hexagon::C2_cmpeqi:
    case Hexagon::C2_cmpgti:
    case Hexagon::C4_cmpltei:
    case Hexagon::C4_cmpneqi: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(512)) << 12;
      Value |= (op & UINT64_C(511)) << 5;
      break;
    }
    case Hexagon::V6_vandvrt:
    case Hexagon::V6_vandvrt_128B:
    case Hexagon::V6_veqb:
    case Hexagon::V6_veqb_128B:
    case Hexagon::V6_veqh:
    case Hexagon::V6_veqh_128B:
    case Hexagon::V6_veqw:
    case Hexagon::V6_veqw_128B:
    case Hexagon::V6_vgtb:
    case Hexagon::V6_vgtb_128B:
    case Hexagon::V6_vgth:
    case Hexagon::V6_vgth_128B:
    case Hexagon::V6_vgtub:
    case Hexagon::V6_vgtub_128B:
    case Hexagon::V6_vgtuh:
    case Hexagon::V6_vgtuh_128B:
    case Hexagon::V6_vgtuw:
    case Hexagon::V6_vgtuw_128B:
    case Hexagon::V6_vgtw:
    case Hexagon::V6_vgtw_128B: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::V6_vandvrt_acc:
    case Hexagon::V6_vandvrt_acc_128B:
    case Hexagon::V6_veqb_and:
    case Hexagon::V6_veqb_and_128B:
    case Hexagon::V6_veqb_or:
    case Hexagon::V6_veqb_or_128B:
    case Hexagon::V6_veqb_xor:
    case Hexagon::V6_veqb_xor_128B:
    case Hexagon::V6_veqh_and:
    case Hexagon::V6_veqh_and_128B:
    case Hexagon::V6_veqh_or:
    case Hexagon::V6_veqh_or_128B:
    case Hexagon::V6_veqh_xor:
    case Hexagon::V6_veqh_xor_128B:
    case Hexagon::V6_veqw_and:
    case Hexagon::V6_veqw_and_128B:
    case Hexagon::V6_veqw_or:
    case Hexagon::V6_veqw_or_128B:
    case Hexagon::V6_veqw_xor:
    case Hexagon::V6_veqw_xor_128B:
    case Hexagon::V6_vgtb_and:
    case Hexagon::V6_vgtb_and_128B:
    case Hexagon::V6_vgtb_or:
    case Hexagon::V6_vgtb_or_128B:
    case Hexagon::V6_vgtb_xor:
    case Hexagon::V6_vgtb_xor_128B:
    case Hexagon::V6_vgth_and:
    case Hexagon::V6_vgth_and_128B:
    case Hexagon::V6_vgth_or:
    case Hexagon::V6_vgth_or_128B:
    case Hexagon::V6_vgth_xor:
    case Hexagon::V6_vgth_xor_128B:
    case Hexagon::V6_vgtub_and:
    case Hexagon::V6_vgtub_and_128B:
    case Hexagon::V6_vgtub_or:
    case Hexagon::V6_vgtub_or_128B:
    case Hexagon::V6_vgtub_xor:
    case Hexagon::V6_vgtub_xor_128B:
    case Hexagon::V6_vgtuh_and:
    case Hexagon::V6_vgtuh_and_128B:
    case Hexagon::V6_vgtuh_or:
    case Hexagon::V6_vgtuh_or_128B:
    case Hexagon::V6_vgtuh_xor:
    case Hexagon::V6_vgtuh_xor_128B:
    case Hexagon::V6_vgtuw_and:
    case Hexagon::V6_vgtuw_and_128B:
    case Hexagon::V6_vgtuw_or:
    case Hexagon::V6_vgtuw_or_128B:
    case Hexagon::V6_vgtuw_xor:
    case Hexagon::V6_vgtuw_xor_128B:
    case Hexagon::V6_vgtw_and:
    case Hexagon::V6_vgtw_and_128B:
    case Hexagon::V6_vgtw_or:
    case Hexagon::V6_vgtw_or_128B:
    case Hexagon::V6_vgtw_xor:
    case Hexagon::V6_vgtw_xor_128B: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::L2_loadalignb_pbr:
    case Hexagon::L2_loadalignh_pbr:
    case Hexagon::L2_loadbsw2_pbr:
    case Hexagon::L2_loadbsw2_pcr:
    case Hexagon::L2_loadbsw4_pbr:
    case Hexagon::L2_loadbsw4_pcr:
    case Hexagon::L2_loadbzw2_pbr:
    case Hexagon::L2_loadbzw2_pcr:
    case Hexagon::L2_loadbzw4_pbr:
    case Hexagon::L2_loadbzw4_pcr:
    case Hexagon::L2_loadrb_pbr:
    case Hexagon::L2_loadrb_pcr:
    case Hexagon::L2_loadrd_pbr:
    case Hexagon::L2_loadrd_pcr:
    case Hexagon::L2_loadrh_pbr:
    case Hexagon::L2_loadrh_pcr:
    case Hexagon::L2_loadri_pbr:
    case Hexagon::L2_loadri_pcr:
    case Hexagon::L2_loadrub_pbr:
    case Hexagon::L2_loadrub_pcr:
    case Hexagon::L2_loadruh_pbr:
    case Hexagon::L2_loadruh_pcr: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rz
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Mu
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(1)) << 13;
      break;
    }
    case Hexagon::L2_loadrd_pci: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rz
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Mu
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(1)) << 13;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(120)) << 2;
      break;
    }
    case Hexagon::L2_loadalignb_pci:
    case Hexagon::L2_loadrb_pci:
    case Hexagon::L2_loadrub_pci: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rz
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Mu
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(1)) << 13;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 5;
      break;
    }
    case Hexagon::L2_loadalignh_pci:
    case Hexagon::L2_loadbsw2_pci:
    case Hexagon::L2_loadbzw2_pci:
    case Hexagon::L2_loadrh_pci:
    case Hexagon::L2_loadruh_pci: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rz
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Mu
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(1)) << 13;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(30)) << 4;
      break;
    }
    case Hexagon::L2_loadbsw4_pci:
    case Hexagon::L2_loadbzw4_pci:
    case Hexagon::L2_loadri_pci: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rz
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Mu
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(1)) << 13;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(60)) << 3;
      break;
    }
    case Hexagon::L2_loadalignb_pcr:
    case Hexagon::L2_loadalignh_pcr: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: Rz
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: Mu
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(1)) << 13;
      break;
    }
    case Hexagon::L2_loadrigp:
    case Hexagon::L4_loadri_abs: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: addr
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(196608)) << 9;
      Value |= (op & UINT64_C(63488)) << 5;
      Value |= (op & UINT64_C(2044)) << 3;
      break;
    }
    case Hexagon::L2_loadrdgp:
    case Hexagon::L4_loadrd_abs: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: addr
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(393216)) << 8;
      Value |= (op & UINT64_C(126976)) << 4;
      Value |= (op & UINT64_C(4088)) << 2;
      break;
    }
    case Hexagon::L2_loadrbgp:
    case Hexagon::L2_loadrubgp:
    case Hexagon::L4_loadrb_abs:
    case Hexagon::L4_loadrub_abs: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: addr
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(49152)) << 11;
      Value |= (op & UINT64_C(15872)) << 7;
      Value |= (op & UINT64_C(511)) << 5;
      break;
    }
    case Hexagon::L2_loadrhgp:
    case Hexagon::L2_loadruhgp:
    case Hexagon::L4_loadrh_abs:
    case Hexagon::L4_loadruh_abs: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: addr
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(98304)) << 10;
      Value |= (op & UINT64_C(31744)) << 6;
      Value |= (op & UINT64_C(1022)) << 4;
      break;
    }
    case Hexagon::A2_abs:
    case Hexagon::A2_abssat:
    case Hexagon::A2_negsat:
    case Hexagon::A2_roundsat:
    case Hexagon::A2_sat:
    case Hexagon::A2_satb:
    case Hexagon::A2_sath:
    case Hexagon::A2_satub:
    case Hexagon::A2_satuh:
    case Hexagon::A2_swiz:
    case Hexagon::A2_sxtw:
    case Hexagon::A2_tfr:
    case Hexagon::A2_tfrcrr:
    case Hexagon::A2_tfrrcr:
    case Hexagon::A4_tfrcpp:
    case Hexagon::A4_tfrpcp:
    case Hexagon::L2_loadw_locked:
    case Hexagon::L4_loadd_locked:
    case Hexagon::S2_brev:
    case Hexagon::S2_svsathb:
    case Hexagon::S2_svsathub:
    case Hexagon::S2_vrndpackwh:
    case Hexagon::S2_vrndpackwhs:
    case Hexagon::S2_vsathb:
    case Hexagon::S2_vsathub:
    case Hexagon::S2_vsatwh:
    case Hexagon::S2_vsatwuh:
    case Hexagon::S2_vsplatrb:
    case Hexagon::S2_vsplatrh:
    case Hexagon::S2_vsxtbh:
    case Hexagon::S2_vsxthw:
    case Hexagon::S2_vtrunehb:
    case Hexagon::S2_vtrunohb:
    case Hexagon::S2_vzxtbh:
    case Hexagon::S2_vzxthw: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::A4_bitspliti:
    case Hexagon::A4_cround_ri:
    case Hexagon::A4_round_ri:
    case Hexagon::A4_round_ri_sat:
    case Hexagon::S2_asl_i_r:
    case Hexagon::S2_asl_i_r_sat:
    case Hexagon::S2_asr_i_r:
    case Hexagon::S2_asr_i_r_rnd:
    case Hexagon::S2_asr_i_svw_trun:
    case Hexagon::S2_lsr_i_r: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: u5
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::F2_dfimm_n:
    case Hexagon::F2_dfimm_p:
    case Hexagon::F2_sfimm_n:
    case Hexagon::F2_sfimm_p: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(512)) << 12;
      Value |= (op & UINT64_C(511)) << 5;
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
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 11;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(126)) << 4;
      break;
    }
    case Hexagon::L2_ploadrif_io:
    case Hexagon::L2_ploadrifnew_io:
    case Hexagon::L2_ploadrit_io:
    case Hexagon::L2_ploadritnew_io: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 11;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(252)) << 3;
      break;
    }
    case Hexagon::L2_ploadrdf_io:
    case Hexagon::L2_ploadrdfnew_io:
    case Hexagon::L2_ploadrdt_io:
    case Hexagon::L2_ploadrdtnew_io: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 11;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(504)) << 2;
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
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 11;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(63)) << 5;
      break;
    }
    case Hexagon::A2_tfrf:
    case Hexagon::A2_tfrfnew:
    case Hexagon::A2_tfrt:
    case Hexagon::A2_tfrtnew: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 21;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::L4_ploadrbf_rr:
    case Hexagon::L4_ploadrbfnew_rr:
    case Hexagon::L4_ploadrbt_rr:
    case Hexagon::L4_ploadrbtnew_rr:
    case Hexagon::L4_ploadrdf_rr:
    case Hexagon::L4_ploadrdfnew_rr:
    case Hexagon::L4_ploadrdt_rr:
    case Hexagon::L4_ploadrdtnew_rr:
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
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 5;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: u2
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(2)) << 12;
      Value |= (op & UINT64_C(1)) << 7;
      break;
    }
    case Hexagon::V6_vmux:
    case Hexagon::V6_vmux_128B:
    case Hexagon::V6_vswap:
    case Hexagon::V6_vswap_128B: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 5;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::V6_vandqrt:
    case Hexagon::V6_vandqrt_128B: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 8;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::L4_ploadrbf_abs:
    case Hexagon::L4_ploadrbfnew_abs:
    case Hexagon::L4_ploadrbt_abs:
    case Hexagon::L4_ploadrbtnew_abs:
    case Hexagon::L4_ploadrdf_abs:
    case Hexagon::L4_ploadrdfnew_abs:
    case Hexagon::L4_ploadrdt_abs:
    case Hexagon::L4_ploadrdtnew_abs:
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
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 9;
      // op: absaddr
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(62)) << 15;
      Value |= (op & UINT64_C(1)) << 8;
      break;
    }
    case Hexagon::V6_lvsplatw:
    case Hexagon::V6_lvsplatw_128B: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::L2_loadrd_io: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(12288)) << 13;
      Value |= (op & UINT64_C(4088)) << 2;
      break;
    }
    case Hexagon::L2_loadrb_io:
    case Hexagon::L2_loadrub_io: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(1536)) << 16;
      Value |= (op & UINT64_C(511)) << 5;
      break;
    }
    case Hexagon::L2_loadbsw2_io:
    case Hexagon::L2_loadbzw2_io:
    case Hexagon::L2_loadrh_io:
    case Hexagon::L2_loadruh_io: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(3072)) << 15;
      Value |= (op & UINT64_C(1022)) << 4;
      break;
    }
    case Hexagon::L2_loadbsw4_io:
    case Hexagon::L2_loadbzw4_io:
    case Hexagon::L2_loadri_io: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(6144)) << 14;
      Value |= (op & UINT64_C(2044)) << 3;
      break;
    }
    case Hexagon::V6_vL32Ub_ai_128B:
    case Hexagon::V6_vL32b_ai_128B:
    case Hexagon::V6_vL32b_cur_ai_128B:
    case Hexagon::V6_vL32b_nt_ai_128B:
    case Hexagon::V6_vL32b_nt_cur_ai_128B:
    case Hexagon::V6_vL32b_nt_tmp_ai_128B:
    case Hexagon::V6_vL32b_tmp_ai_128B: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(1024)) << 3;
      Value |= (op & UINT64_C(896)) << 1;
      break;
    }
    case Hexagon::L4_loadalignb_ur:
    case Hexagon::L4_loadalignh_ur:
    case Hexagon::L4_loadbsw2_ur:
    case Hexagon::L4_loadbsw4_ur:
    case Hexagon::L4_loadbzw2_ur:
    case Hexagon::L4_loadbzw4_ur:
    case Hexagon::L4_loadrb_ur:
    case Hexagon::L4_loadrd_ur:
    case Hexagon::L4_loadrh_ur:
    case Hexagon::L4_loadri_ur:
    case Hexagon::L4_loadrub_ur:
    case Hexagon::L4_loadruh_ur: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(2)) << 12;
      Value |= (op & UINT64_C(1)) << 7;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(60)) << 6;
      Value |= (op & UINT64_C(3)) << 5;
      break;
    }
    case Hexagon::A4_cround_rr:
    case Hexagon::A4_round_rr:
    case Hexagon::A4_round_rr_sat:
    case Hexagon::A5_vaddhubs:
    case Hexagon::M2_cmpyrs_s0:
    case Hexagon::M2_cmpyrs_s1:
    case Hexagon::M2_cmpyrsc_s0:
    case Hexagon::M2_cmpyrsc_s1:
    case Hexagon::M2_dpmpyss_rnd_s0:
    case Hexagon::M2_hmmpyh_rs1:
    case Hexagon::M2_hmmpyh_s1:
    case Hexagon::M2_hmmpyl_rs1:
    case Hexagon::M2_hmmpyl_s1:
    case Hexagon::M2_mpy_up:
    case Hexagon::M2_mpy_up_s1:
    case Hexagon::M2_mpy_up_s1_sat:
    case Hexagon::M2_mpyi:
    case Hexagon::M2_mpysu_up:
    case Hexagon::M2_mpyu_up:
    case Hexagon::M2_vdmpyrs_s0:
    case Hexagon::M2_vdmpyrs_s1:
    case Hexagon::M2_vmpy2s_s0pack:
    case Hexagon::M2_vmpy2s_s1pack:
    case Hexagon::M2_vraddh:
    case Hexagon::M2_vradduh:
    case Hexagon::M2_vrcmpys_s1rp_h:
    case Hexagon::M2_vrcmpys_s1rp_l:
    case Hexagon::S2_asl_r_p:
    case Hexagon::S2_asl_r_r:
    case Hexagon::S2_asl_r_r_sat:
    case Hexagon::S2_asl_r_vh:
    case Hexagon::S2_asl_r_vw:
    case Hexagon::S2_asr_r_p:
    case Hexagon::S2_asr_r_r:
    case Hexagon::S2_asr_r_r_sat:
    case Hexagon::S2_asr_r_vh:
    case Hexagon::S2_asr_r_vw:
    case Hexagon::S2_cabacdecbin:
    case Hexagon::S2_extractup_rp:
    case Hexagon::S2_lfsp:
    case Hexagon::S2_lsl_r_p:
    case Hexagon::S2_lsl_r_r:
    case Hexagon::S2_lsl_r_vh:
    case Hexagon::S2_lsl_r_vw:
    case Hexagon::S2_lsr_r_p:
    case Hexagon::S2_lsr_r_r:
    case Hexagon::S2_lsr_r_vh:
    case Hexagon::S2_lsr_r_vw:
    case Hexagon::S2_shuffeb:
    case Hexagon::S2_shuffeh:
    case Hexagon::S2_vcnegh:
    case Hexagon::S2_vcrotate:
    case Hexagon::S2_vtrunewh:
    case Hexagon::S2_vtrunowh:
    case Hexagon::S4_extractp_rp:
    case Hexagon::S4_vxaddsubh:
    case Hexagon::S4_vxaddsubhr:
    case Hexagon::S4_vxaddsubw:
    case Hexagon::S4_vxsubaddh:
    case Hexagon::S4_vxsubaddhr:
    case Hexagon::S4_vxsubaddw:
    case Hexagon::S6_rol_i_r: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S2_extractu:
    case Hexagon::S4_extract: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(24)) << 18;
      Value |= (op & UINT64_C(7)) << 5;
      break;
    }
    case Hexagon::S2_cabacencbin: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 5;
      break;
    }
    case Hexagon::L4_loadrb_rr:
    case Hexagon::L4_loadrd_rr:
    case Hexagon::L4_loadrh_rr:
    case Hexagon::L4_loadri_rr:
    case Hexagon::L4_loadrub_rr:
    case Hexagon::L4_loadruh_rr: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: u2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(2)) << 12;
      Value |= (op & UINT64_C(1)) << 7;
      break;
    }
    case Hexagon::V6_vL32Ub_ai:
    case Hexagon::V6_vL32b_ai:
    case Hexagon::V6_vL32b_cur_ai:
    case Hexagon::V6_vL32b_nt_ai:
    case Hexagon::V6_vL32b_nt_cur_ai:
    case Hexagon::V6_vL32b_nt_tmp_ai:
    case Hexagon::V6_vL32b_tmp_ai: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(512)) << 4;
      Value |= (op & UINT64_C(448)) << 2;
      break;
    }
    case Hexagon::S6_rol_i_p: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(63)) << 8;
      break;
    }
    case Hexagon::S2_extractup:
    case Hexagon::S4_extractp: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(63)) << 8;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(56)) << 18;
      Value |= (op & UINT64_C(7)) << 5;
      break;
    }
    case Hexagon::V6_vabsh:
    case Hexagon::V6_vabsh_128B:
    case Hexagon::V6_vabsh_sat:
    case Hexagon::V6_vabsh_sat_128B:
    case Hexagon::V6_vabsw:
    case Hexagon::V6_vabsw_128B:
    case Hexagon::V6_vabsw_sat:
    case Hexagon::V6_vabsw_sat_128B:
    case Hexagon::V6_vassign:
    case Hexagon::V6_vassign_128B:
    case Hexagon::V6_vcl0h:
    case Hexagon::V6_vcl0h_128B:
    case Hexagon::V6_vcl0w:
    case Hexagon::V6_vcl0w_128B:
    case Hexagon::V6_vdealb:
    case Hexagon::V6_vdealb_128B:
    case Hexagon::V6_vdealh:
    case Hexagon::V6_vdealh_128B:
    case Hexagon::V6_vnormamth:
    case Hexagon::V6_vnormamth_128B:
    case Hexagon::V6_vnormamtw:
    case Hexagon::V6_vnormamtw_128B:
    case Hexagon::V6_vnot:
    case Hexagon::V6_vnot_128B:
    case Hexagon::V6_vpopcounth:
    case Hexagon::V6_vpopcounth_128B:
    case Hexagon::V6_vsb:
    case Hexagon::V6_vsb_128B:
    case Hexagon::V6_vsh:
    case Hexagon::V6_vsh_128B:
    case Hexagon::V6_vshuffb:
    case Hexagon::V6_vshuffb_128B:
    case Hexagon::V6_vshuffh:
    case Hexagon::V6_vshuffh_128B:
    case Hexagon::V6_vunpackb:
    case Hexagon::V6_vunpackb_128B:
    case Hexagon::V6_vunpackh:
    case Hexagon::V6_vunpackh_128B:
    case Hexagon::V6_vunpackub:
    case Hexagon::V6_vunpackub_128B:
    case Hexagon::V6_vunpackuh:
    case Hexagon::V6_vunpackuh_128B:
    case Hexagon::V6_vzb:
    case Hexagon::V6_vzb_128B:
    case Hexagon::V6_vzh:
    case Hexagon::V6_vzh_128B: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S2_shuffob:
    case Hexagon::S2_shuffoh:
    case Hexagon::V6_extractw:
    case Hexagon::V6_extractw_128B:
    case Hexagon::V6_vabsdiffh:
    case Hexagon::V6_vabsdiffh_128B:
    case Hexagon::V6_vabsdiffub:
    case Hexagon::V6_vabsdiffub_128B:
    case Hexagon::V6_vabsdiffuh:
    case Hexagon::V6_vabsdiffuh_128B:
    case Hexagon::V6_vabsdiffw:
    case Hexagon::V6_vabsdiffw_128B:
    case Hexagon::V6_vaddb:
    case Hexagon::V6_vaddb_128B:
    case Hexagon::V6_vaddb_dv:
    case Hexagon::V6_vaddb_dv_128B:
    case Hexagon::V6_vaddh:
    case Hexagon::V6_vaddh_128B:
    case Hexagon::V6_vaddh_dv:
    case Hexagon::V6_vaddh_dv_128B:
    case Hexagon::V6_vaddhsat:
    case Hexagon::V6_vaddhsat_128B:
    case Hexagon::V6_vaddhsat_dv:
    case Hexagon::V6_vaddhsat_dv_128B:
    case Hexagon::V6_vaddhw:
    case Hexagon::V6_vaddhw_128B:
    case Hexagon::V6_vaddubh:
    case Hexagon::V6_vaddubh_128B:
    case Hexagon::V6_vaddubsat:
    case Hexagon::V6_vaddubsat_128B:
    case Hexagon::V6_vaddubsat_dv:
    case Hexagon::V6_vaddubsat_dv_128B:
    case Hexagon::V6_vadduhsat:
    case Hexagon::V6_vadduhsat_128B:
    case Hexagon::V6_vadduhsat_dv:
    case Hexagon::V6_vadduhsat_dv_128B:
    case Hexagon::V6_vadduhw:
    case Hexagon::V6_vadduhw_128B:
    case Hexagon::V6_vaddw:
    case Hexagon::V6_vaddw_128B:
    case Hexagon::V6_vaddw_dv:
    case Hexagon::V6_vaddw_dv_128B:
    case Hexagon::V6_vaddwsat:
    case Hexagon::V6_vaddwsat_128B:
    case Hexagon::V6_vaddwsat_dv:
    case Hexagon::V6_vaddwsat_dv_128B:
    case Hexagon::V6_vand:
    case Hexagon::V6_vand_128B:
    case Hexagon::V6_vaslh:
    case Hexagon::V6_vaslh_128B:
    case Hexagon::V6_vaslhv:
    case Hexagon::V6_vaslhv_128B:
    case Hexagon::V6_vaslw:
    case Hexagon::V6_vaslw_128B:
    case Hexagon::V6_vaslwv:
    case Hexagon::V6_vaslwv_128B:
    case Hexagon::V6_vasrh:
    case Hexagon::V6_vasrh_128B:
    case Hexagon::V6_vasrhv:
    case Hexagon::V6_vasrhv_128B:
    case Hexagon::V6_vasrw:
    case Hexagon::V6_vasrw_128B:
    case Hexagon::V6_vasrwv:
    case Hexagon::V6_vasrwv_128B:
    case Hexagon::V6_vavgh:
    case Hexagon::V6_vavgh_128B:
    case Hexagon::V6_vavghrnd:
    case Hexagon::V6_vavghrnd_128B:
    case Hexagon::V6_vavgub:
    case Hexagon::V6_vavgub_128B:
    case Hexagon::V6_vavgubrnd:
    case Hexagon::V6_vavgubrnd_128B:
    case Hexagon::V6_vavguh:
    case Hexagon::V6_vavguh_128B:
    case Hexagon::V6_vavguhrnd:
    case Hexagon::V6_vavguhrnd_128B:
    case Hexagon::V6_vavgw:
    case Hexagon::V6_vavgw_128B:
    case Hexagon::V6_vavgwrnd:
    case Hexagon::V6_vavgwrnd_128B:
    case Hexagon::V6_vcombine:
    case Hexagon::V6_vcombine_128B:
    case Hexagon::V6_vdealb4w:
    case Hexagon::V6_vdealb4w_128B:
    case Hexagon::V6_vdelta:
    case Hexagon::V6_vdelta_128B:
    case Hexagon::V6_vdmpybus:
    case Hexagon::V6_vdmpybus_128B:
    case Hexagon::V6_vdmpybus_dv:
    case Hexagon::V6_vdmpybus_dv_128B:
    case Hexagon::V6_vdmpyhb:
    case Hexagon::V6_vdmpyhb_128B:
    case Hexagon::V6_vdmpyhb_dv:
    case Hexagon::V6_vdmpyhb_dv_128B:
    case Hexagon::V6_vdmpyhisat:
    case Hexagon::V6_vdmpyhisat_128B:
    case Hexagon::V6_vdmpyhsat:
    case Hexagon::V6_vdmpyhsat_128B:
    case Hexagon::V6_vdmpyhsuisat:
    case Hexagon::V6_vdmpyhsuisat_128B:
    case Hexagon::V6_vdmpyhsusat:
    case Hexagon::V6_vdmpyhsusat_128B:
    case Hexagon::V6_vdmpyhvsat:
    case Hexagon::V6_vdmpyhvsat_128B:
    case Hexagon::V6_vdsaduh:
    case Hexagon::V6_vdsaduh_128B:
    case Hexagon::V6_vlsrh:
    case Hexagon::V6_vlsrh_128B:
    case Hexagon::V6_vlsrhv:
    case Hexagon::V6_vlsrhv_128B:
    case Hexagon::V6_vlsrw:
    case Hexagon::V6_vlsrw_128B:
    case Hexagon::V6_vlsrwv:
    case Hexagon::V6_vlsrwv_128B:
    case Hexagon::V6_vmaxh:
    case Hexagon::V6_vmaxh_128B:
    case Hexagon::V6_vmaxub:
    case Hexagon::V6_vmaxub_128B:
    case Hexagon::V6_vmaxuh:
    case Hexagon::V6_vmaxuh_128B:
    case Hexagon::V6_vmaxw:
    case Hexagon::V6_vmaxw_128B:
    case Hexagon::V6_vminh:
    case Hexagon::V6_vminh_128B:
    case Hexagon::V6_vminub:
    case Hexagon::V6_vminub_128B:
    case Hexagon::V6_vminuh:
    case Hexagon::V6_vminuh_128B:
    case Hexagon::V6_vminw:
    case Hexagon::V6_vminw_128B:
    case Hexagon::V6_vmpabus:
    case Hexagon::V6_vmpabus_128B:
    case Hexagon::V6_vmpabusv:
    case Hexagon::V6_vmpabusv_128B:
    case Hexagon::V6_vmpabuuv:
    case Hexagon::V6_vmpabuuv_128B:
    case Hexagon::V6_vmpahb:
    case Hexagon::V6_vmpahb_128B:
    case Hexagon::V6_vmpybus:
    case Hexagon::V6_vmpybus_128B:
    case Hexagon::V6_vmpybusv:
    case Hexagon::V6_vmpybusv_128B:
    case Hexagon::V6_vmpybv:
    case Hexagon::V6_vmpybv_128B:
    case Hexagon::V6_vmpyewuh:
    case Hexagon::V6_vmpyewuh_128B:
    case Hexagon::V6_vmpyh:
    case Hexagon::V6_vmpyh_128B:
    case Hexagon::V6_vmpyhsrs:
    case Hexagon::V6_vmpyhsrs_128B:
    case Hexagon::V6_vmpyhss:
    case Hexagon::V6_vmpyhss_128B:
    case Hexagon::V6_vmpyhus:
    case Hexagon::V6_vmpyhus_128B:
    case Hexagon::V6_vmpyhv:
    case Hexagon::V6_vmpyhv_128B:
    case Hexagon::V6_vmpyhvsrs:
    case Hexagon::V6_vmpyhvsrs_128B:
    case Hexagon::V6_vmpyieoh:
    case Hexagon::V6_vmpyieoh_128B:
    case Hexagon::V6_vmpyiewuh:
    case Hexagon::V6_vmpyiewuh_128B:
    case Hexagon::V6_vmpyih:
    case Hexagon::V6_vmpyih_128B:
    case Hexagon::V6_vmpyihb:
    case Hexagon::V6_vmpyihb_128B:
    case Hexagon::V6_vmpyiowh:
    case Hexagon::V6_vmpyiowh_128B:
    case Hexagon::V6_vmpyiwb:
    case Hexagon::V6_vmpyiwb_128B:
    case Hexagon::V6_vmpyiwh:
    case Hexagon::V6_vmpyiwh_128B:
    case Hexagon::V6_vmpyowh:
    case Hexagon::V6_vmpyowh_128B:
    case Hexagon::V6_vmpyowh_rnd:
    case Hexagon::V6_vmpyowh_rnd_128B:
    case Hexagon::V6_vmpyub:
    case Hexagon::V6_vmpyub_128B:
    case Hexagon::V6_vmpyubv:
    case Hexagon::V6_vmpyubv_128B:
    case Hexagon::V6_vmpyuh:
    case Hexagon::V6_vmpyuh_128B:
    case Hexagon::V6_vmpyuhv:
    case Hexagon::V6_vmpyuhv_128B:
    case Hexagon::V6_vnavgh:
    case Hexagon::V6_vnavgh_128B:
    case Hexagon::V6_vnavgub:
    case Hexagon::V6_vnavgub_128B:
    case Hexagon::V6_vnavgw:
    case Hexagon::V6_vnavgw_128B:
    case Hexagon::V6_vor:
    case Hexagon::V6_vor_128B:
    case Hexagon::V6_vpackeb:
    case Hexagon::V6_vpackeb_128B:
    case Hexagon::V6_vpackeh:
    case Hexagon::V6_vpackeh_128B:
    case Hexagon::V6_vpackhb_sat:
    case Hexagon::V6_vpackhb_sat_128B:
    case Hexagon::V6_vpackhub_sat:
    case Hexagon::V6_vpackhub_sat_128B:
    case Hexagon::V6_vpackob:
    case Hexagon::V6_vpackob_128B:
    case Hexagon::V6_vpackoh:
    case Hexagon::V6_vpackoh_128B:
    case Hexagon::V6_vpackwh_sat:
    case Hexagon::V6_vpackwh_sat_128B:
    case Hexagon::V6_vpackwuh_sat:
    case Hexagon::V6_vpackwuh_sat_128B:
    case Hexagon::V6_vrdelta:
    case Hexagon::V6_vrdelta_128B:
    case Hexagon::V6_vrmpybus:
    case Hexagon::V6_vrmpybus_128B:
    case Hexagon::V6_vrmpybusv:
    case Hexagon::V6_vrmpybusv_128B:
    case Hexagon::V6_vrmpybv:
    case Hexagon::V6_vrmpybv_128B:
    case Hexagon::V6_vrmpyub:
    case Hexagon::V6_vrmpyub_128B:
    case Hexagon::V6_vrmpyubv:
    case Hexagon::V6_vrmpyubv_128B:
    case Hexagon::V6_vror:
    case Hexagon::V6_vror_128B:
    case Hexagon::V6_vroundhb:
    case Hexagon::V6_vroundhb_128B:
    case Hexagon::V6_vroundhub:
    case Hexagon::V6_vroundhub_128B:
    case Hexagon::V6_vroundwh:
    case Hexagon::V6_vroundwh_128B:
    case Hexagon::V6_vroundwuh:
    case Hexagon::V6_vroundwuh_128B:
    case Hexagon::V6_vsathub:
    case Hexagon::V6_vsathub_128B:
    case Hexagon::V6_vsatwh:
    case Hexagon::V6_vsatwh_128B:
    case Hexagon::V6_vshufeh:
    case Hexagon::V6_vshufeh_128B:
    case Hexagon::V6_vshuffeb:
    case Hexagon::V6_vshuffeb_128B:
    case Hexagon::V6_vshuffob:
    case Hexagon::V6_vshuffob_128B:
    case Hexagon::V6_vshufoeb:
    case Hexagon::V6_vshufoeb_128B:
    case Hexagon::V6_vshufoeh:
    case Hexagon::V6_vshufoeh_128B:
    case Hexagon::V6_vshufoh:
    case Hexagon::V6_vshufoh_128B:
    case Hexagon::V6_vsubb:
    case Hexagon::V6_vsubb_128B:
    case Hexagon::V6_vsubb_dv:
    case Hexagon::V6_vsubb_dv_128B:
    case Hexagon::V6_vsubh:
    case Hexagon::V6_vsubh_128B:
    case Hexagon::V6_vsubh_dv:
    case Hexagon::V6_vsubh_dv_128B:
    case Hexagon::V6_vsubhsat:
    case Hexagon::V6_vsubhsat_128B:
    case Hexagon::V6_vsubhsat_dv:
    case Hexagon::V6_vsubhsat_dv_128B:
    case Hexagon::V6_vsubhw:
    case Hexagon::V6_vsubhw_128B:
    case Hexagon::V6_vsububh:
    case Hexagon::V6_vsububh_128B:
    case Hexagon::V6_vsububsat:
    case Hexagon::V6_vsububsat_128B:
    case Hexagon::V6_vsububsat_dv:
    case Hexagon::V6_vsububsat_dv_128B:
    case Hexagon::V6_vsubuhsat:
    case Hexagon::V6_vsubuhsat_128B:
    case Hexagon::V6_vsubuhsat_dv:
    case Hexagon::V6_vsubuhsat_dv_128B:
    case Hexagon::V6_vsubuhw:
    case Hexagon::V6_vsubuhw_128B:
    case Hexagon::V6_vsubw:
    case Hexagon::V6_vsubw_128B:
    case Hexagon::V6_vsubw_dv:
    case Hexagon::V6_vsubw_dv_128B:
    case Hexagon::V6_vsubwsat:
    case Hexagon::V6_vsubwsat_128B:
    case Hexagon::V6_vsubwsat_dv:
    case Hexagon::V6_vsubwsat_dv_128B:
    case Hexagon::V6_vtmpyb:
    case Hexagon::V6_vtmpyb_128B:
    case Hexagon::V6_vtmpybus:
    case Hexagon::V6_vtmpybus_128B:
    case Hexagon::V6_vtmpyhb:
    case Hexagon::V6_vtmpyhb_128B:
    case Hexagon::V6_vxor:
    case Hexagon::V6_vxor_128B: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::V6_vrmpybusi:
    case Hexagon::V6_vrmpybusi_128B:
    case Hexagon::V6_vrmpyubi:
    case Hexagon::V6_vrmpyubi_128B:
    case Hexagon::V6_vrsadubi:
    case Hexagon::V6_vrsadubi_128B: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(1)) << 5;
      break;
    }
    case Hexagon::V6_valignbi:
    case Hexagon::V6_valignbi_128B:
    case Hexagon::V6_vlalignbi:
    case Hexagon::V6_vlalignbi_128B: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 5;
      break;
    }
    case Hexagon::V6_valignb:
    case Hexagon::V6_valignb_128B:
    case Hexagon::V6_vasrhbrndsat:
    case Hexagon::V6_vasrhbrndsat_128B:
    case Hexagon::V6_vasrhubrndsat:
    case Hexagon::V6_vasrhubrndsat_128B:
    case Hexagon::V6_vasrhubsat:
    case Hexagon::V6_vasrhubsat_128B:
    case Hexagon::V6_vasrwh:
    case Hexagon::V6_vasrwh_128B:
    case Hexagon::V6_vasrwhrndsat:
    case Hexagon::V6_vasrwhrndsat_128B:
    case Hexagon::V6_vasrwhsat:
    case Hexagon::V6_vasrwhsat_128B:
    case Hexagon::V6_vasrwuhsat:
    case Hexagon::V6_vasrwuhsat_128B:
    case Hexagon::V6_vdealvdd:
    case Hexagon::V6_vdealvdd_128B:
    case Hexagon::V6_vlalignb:
    case Hexagon::V6_vlalignb_128B:
    case Hexagon::V6_vlutvvb:
    case Hexagon::V6_vlutvvb_128B:
    case Hexagon::V6_vlutvwh:
    case Hexagon::V6_vlutvwh_128B:
    case Hexagon::V6_vshuffvdd:
    case Hexagon::V6_vshuffvdd_128B: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 19;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 16;
      break;
    }
    case Hexagon::V6_vandqrt_acc:
    case Hexagon::V6_vandqrt_acc_128B: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 8;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::L2_ploadrdf_pi:
    case Hexagon::L2_ploadrdfnew_pi:
    case Hexagon::L2_ploadrdt_pi:
    case Hexagon::L2_ploadrdtnew_pi: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 9;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(120)) << 2;
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
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 9;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 5;
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
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 9;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(30)) << 4;
      break;
    }
    case Hexagon::L2_ploadrif_pi:
    case Hexagon::L2_ploadrifnew_pi:
    case Hexagon::L2_ploadrit_pi:
    case Hexagon::L2_ploadritnew_pi: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 9;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(60)) << 3;
      break;
    }
    case Hexagon::V6_vinsertwr:
    case Hexagon::V6_vinsertwr_128B: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::L2_loadrd_pi: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(120)) << 2;
      break;
    }
    case Hexagon::L2_loadrb_pi:
    case Hexagon::L2_loadrub_pi: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 5;
      break;
    }
    case Hexagon::L2_loadbsw2_pi:
    case Hexagon::L2_loadbzw2_pi:
    case Hexagon::L2_loadrh_pi:
    case Hexagon::L2_loadruh_pi: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(30)) << 4;
      break;
    }
    case Hexagon::L2_loadbsw4_pi:
    case Hexagon::L2_loadbzw4_pi:
    case Hexagon::L2_loadri_pi: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(60)) << 3;
      break;
    }
    case Hexagon::L2_loadbsw2_pr:
    case Hexagon::L2_loadbsw4_pr:
    case Hexagon::L2_loadbzw2_pr:
    case Hexagon::L2_loadbzw4_pr:
    case Hexagon::L2_loadrb_pr:
    case Hexagon::L2_loadrd_pr:
    case Hexagon::L2_loadrh_pr:
    case Hexagon::L2_loadri_pr:
    case Hexagon::L2_loadrub_pr:
    case Hexagon::L2_loadruh_pr:
    case Hexagon::V6_vL32Ub_ppu:
    case Hexagon::V6_vL32b_cur_ppu:
    case Hexagon::V6_vL32b_nt_cur_ppu:
    case Hexagon::V6_vL32b_nt_ppu:
    case Hexagon::V6_vL32b_nt_tmp_ppu:
    case Hexagon::V6_vL32b_ppu:
    case Hexagon::V6_vL32b_tmp_ppu: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(1)) << 13;
      break;
    }
    case Hexagon::S6_rol_i_r_acc:
    case Hexagon::S6_rol_i_r_and:
    case Hexagon::S6_rol_i_r_nac:
    case Hexagon::S6_rol_i_r_or:
    case Hexagon::S6_rol_i_r_xacc: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S2_insert: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(24)) << 18;
      Value |= (op & UINT64_C(7)) << 5;
      break;
    }
    case Hexagon::V6_vL32Ub_pi:
    case Hexagon::V6_vL32b_cur_pi:
    case Hexagon::V6_vL32b_nt_cur_pi:
    case Hexagon::V6_vL32b_nt_pi:
    case Hexagon::V6_vL32b_nt_tmp_pi:
    case Hexagon::V6_vL32b_pi:
    case Hexagon::V6_vL32b_tmp_pi: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(448)) << 2;
      break;
    }
    case Hexagon::S6_rol_i_p_acc:
    case Hexagon::S6_rol_i_p_and:
    case Hexagon::S6_rol_i_p_nac:
    case Hexagon::S6_rol_i_p_or:
    case Hexagon::S6_rol_i_p_xacc: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(63)) << 8;
      break;
    }
    case Hexagon::S2_insertp: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(63)) << 8;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(56)) << 18;
      Value |= (op & UINT64_C(7)) << 5;
      break;
    }
    case Hexagon::V6_vL32Ub_pi_128B:
    case Hexagon::V6_vL32b_cur_pi_128B:
    case Hexagon::V6_vL32b_nt_cur_pi_128B:
    case Hexagon::V6_vL32b_nt_pi_128B:
    case Hexagon::V6_vL32b_nt_tmp_pi_128B:
    case Hexagon::V6_vL32b_pi_128B:
    case Hexagon::V6_vL32b_tmp_pi_128B: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(896)) << 1;
      break;
    }
    case Hexagon::V6_vunpackob:
    case Hexagon::V6_vunpackob_128B:
    case Hexagon::V6_vunpackoh:
    case Hexagon::V6_vunpackoh_128B: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::V6_vaslw_acc:
    case Hexagon::V6_vaslw_acc_128B:
    case Hexagon::V6_vasrw_acc:
    case Hexagon::V6_vasrw_acc_128B:
    case Hexagon::V6_vdmpybus_acc:
    case Hexagon::V6_vdmpybus_acc_128B:
    case Hexagon::V6_vdmpybus_dv_acc:
    case Hexagon::V6_vdmpybus_dv_acc_128B:
    case Hexagon::V6_vdmpyhb_acc:
    case Hexagon::V6_vdmpyhb_acc_128B:
    case Hexagon::V6_vdmpyhb_dv_acc:
    case Hexagon::V6_vdmpyhb_dv_acc_128B:
    case Hexagon::V6_vdmpyhisat_acc:
    case Hexagon::V6_vdmpyhisat_acc_128B:
    case Hexagon::V6_vdmpyhsat_acc:
    case Hexagon::V6_vdmpyhsat_acc_128B:
    case Hexagon::V6_vdmpyhsuisat_acc:
    case Hexagon::V6_vdmpyhsuisat_acc_128B:
    case Hexagon::V6_vdmpyhsusat_acc:
    case Hexagon::V6_vdmpyhsusat_acc_128B:
    case Hexagon::V6_vdmpyhvsat_acc:
    case Hexagon::V6_vdmpyhvsat_acc_128B:
    case Hexagon::V6_vdsaduh_acc:
    case Hexagon::V6_vdsaduh_acc_128B:
    case Hexagon::V6_vmpabus_acc:
    case Hexagon::V6_vmpabus_acc_128B:
    case Hexagon::V6_vmpahb_acc:
    case Hexagon::V6_vmpahb_acc_128B:
    case Hexagon::V6_vmpybus_acc:
    case Hexagon::V6_vmpybus_acc_128B:
    case Hexagon::V6_vmpybusv_acc:
    case Hexagon::V6_vmpybusv_acc_128B:
    case Hexagon::V6_vmpybv_acc:
    case Hexagon::V6_vmpybv_acc_128B:
    case Hexagon::V6_vmpyhsat_acc:
    case Hexagon::V6_vmpyhsat_acc_128B:
    case Hexagon::V6_vmpyhus_acc:
    case Hexagon::V6_vmpyhus_acc_128B:
    case Hexagon::V6_vmpyhv_acc:
    case Hexagon::V6_vmpyhv_acc_128B:
    case Hexagon::V6_vmpyiewh_acc:
    case Hexagon::V6_vmpyiewh_acc_128B:
    case Hexagon::V6_vmpyiewuh_acc:
    case Hexagon::V6_vmpyiewuh_acc_128B:
    case Hexagon::V6_vmpyih_acc:
    case Hexagon::V6_vmpyih_acc_128B:
    case Hexagon::V6_vmpyihb_acc:
    case Hexagon::V6_vmpyihb_acc_128B:
    case Hexagon::V6_vmpyiwb_acc:
    case Hexagon::V6_vmpyiwb_acc_128B:
    case Hexagon::V6_vmpyiwh_acc:
    case Hexagon::V6_vmpyiwh_acc_128B:
    case Hexagon::V6_vmpyowh_rnd_sacc:
    case Hexagon::V6_vmpyowh_rnd_sacc_128B:
    case Hexagon::V6_vmpyowh_sacc:
    case Hexagon::V6_vmpyowh_sacc_128B:
    case Hexagon::V6_vmpyub_acc:
    case Hexagon::V6_vmpyub_acc_128B:
    case Hexagon::V6_vmpyubv_acc:
    case Hexagon::V6_vmpyubv_acc_128B:
    case Hexagon::V6_vmpyuh_acc:
    case Hexagon::V6_vmpyuh_acc_128B:
    case Hexagon::V6_vmpyuhv_acc:
    case Hexagon::V6_vmpyuhv_acc_128B:
    case Hexagon::V6_vrmpybus_acc:
    case Hexagon::V6_vrmpybus_acc_128B:
    case Hexagon::V6_vrmpybusv_acc:
    case Hexagon::V6_vrmpybusv_acc_128B:
    case Hexagon::V6_vrmpybv_acc:
    case Hexagon::V6_vrmpybv_acc_128B:
    case Hexagon::V6_vrmpyub_acc:
    case Hexagon::V6_vrmpyub_acc_128B:
    case Hexagon::V6_vrmpyubv_acc:
    case Hexagon::V6_vrmpyubv_acc_128B:
    case Hexagon::V6_vtmpyb_acc:
    case Hexagon::V6_vtmpyb_acc_128B:
    case Hexagon::V6_vtmpybus_acc:
    case Hexagon::V6_vtmpybus_acc_128B:
    case Hexagon::V6_vtmpyhb_acc:
    case Hexagon::V6_vtmpyhb_acc_128B: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::V6_vrmpybusi_acc:
    case Hexagon::V6_vrmpybusi_acc_128B:
    case Hexagon::V6_vrmpyubi_acc:
    case Hexagon::V6_vrmpyubi_acc_128B:
    case Hexagon::V6_vrsadubi_acc:
    case Hexagon::V6_vrsadubi_acc_128B: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(1)) << 5;
      break;
    }
    case Hexagon::V6_vlutvvb_oracc:
    case Hexagon::V6_vlutvvb_oracc_128B:
    case Hexagon::V6_vlutvwh_oracc:
    case Hexagon::V6_vlutvwh_oracc_128B: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 19;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 16;
      break;
    }
    case Hexagon::L2_loadalignb_io: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(1536)) << 16;
      Value |= (op & UINT64_C(511)) << 5;
      break;
    }
    case Hexagon::L2_loadalignh_io: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(3072)) << 15;
      Value |= (op & UINT64_C(1022)) << 4;
      break;
    }
    case Hexagon::M2_accii:
    case Hexagon::M2_macsin:
    case Hexagon::M2_macsip:
    case Hexagon::M2_naccii: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(255)) << 5;
      break;
    }
    case Hexagon::M2_acci:
    case Hexagon::M2_maci:
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
    case Hexagon::S2_insert_rp:
    case Hexagon::S2_insertp_rp: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::M2_subacc: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::L2_loadalignb_pi: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 5;
      break;
    }
    case Hexagon::L2_loadalignh_pi: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(30)) << 4;
      break;
    }
    case Hexagon::L2_loadalignb_pr:
    case Hexagon::L2_loadalignh_pr: {
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(1)) << 13;
      break;
    }
    case Hexagon::A5_ACS: {
      // op: dst1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: dst2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 5;
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::L4_loadalignb_ap:
    case Hexagon::L4_loadalignh_ap:
    case Hexagon::L4_loadbsw2_ap:
    case Hexagon::L4_loadbsw4_ap:
    case Hexagon::L4_loadbzw2_ap:
    case Hexagon::L4_loadbzw4_ap:
    case Hexagon::L4_loadrb_ap:
    case Hexagon::L4_loadrd_ap:
    case Hexagon::L4_loadrh_ap:
    case Hexagon::L4_loadri_ap:
    case Hexagon::L4_loadrub_ap:
    case Hexagon::L4_loadruh_ap: {
      // op: dst1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: dst2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: addr
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(60)) << 6;
      Value |= (op & UINT64_C(3)) << 5;
      break;
    }
    case Hexagon::A4_ext:
    case Hexagon::A4_ext_b:
    case Hexagon::A4_ext_c:
    case Hexagon::A4_ext_g: {
      // op: imm
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(4293918720)) >> 4;
      Value |= (op & UINT64_C(1048512)) >> 6;
      break;
    }
    case Hexagon::J2_loop0r:
    case Hexagon::J2_loop0rext:
    case Hexagon::J2_loop1r:
    case Hexagon::J2_loop1rext: {
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(496)) << 4;
      Value |= (op & UINT64_C(12)) << 1;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::J2_loop0i:
    case Hexagon::J2_loop0iext:
    case Hexagon::J2_loop1i:
    case Hexagon::J2_loop1iext: {
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(496)) << 4;
      Value |= (op & UINT64_C(12)) << 1;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(992)) << 11;
      Value |= (op & UINT64_C(28)) << 3;
      Value |= op & UINT64_C(3);
      break;
    }
    case Hexagon::J2_ploop1sr:
    case Hexagon::J2_ploop2sr:
    case Hexagon::J2_ploop3sr: {
      // op: r7_2
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(496)) << 4;
      Value |= (op & UINT64_C(12)) << 1;
      // op: Rs
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::J2_ploop1si:
    case Hexagon::J2_ploop2si:
    case Hexagon::J2_ploop3si: {
      // op: r7_2
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(496)) << 4;
      Value |= (op & UINT64_C(12)) << 1;
      // op: U10
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(992)) << 11;
      Value |= (op & UINT64_C(28)) << 3;
      Value |= op & UINT64_C(3);
      break;
    }
    case Hexagon::V4_SS2_stored_sp: {
      // op: s6_3
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(504);
      // op: Rtt
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= op & UINT64_C(7);
      break;
    }
    case Hexagon::L4_return_f:
    case Hexagon::L4_return_fnew_pnt:
    case Hexagon::L4_return_fnew_pt:
    case Hexagon::L4_return_t:
    case Hexagon::L4_return_tnew_pnt:
    case Hexagon::L4_return_tnew_pt: {
      // op: src
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 8;
      break;
    }
    case Hexagon::J2_jumprf:
    case Hexagon::J2_jumprfnew:
    case Hexagon::J2_jumprfnewpt:
    case Hexagon::J2_jumprt:
    case Hexagon::J2_jumprtnew:
    case Hexagon::J2_jumprtnewpt:
    case Hexagon::JMPretf:
    case Hexagon::JMPretfnew:
    case Hexagon::JMPretfnewpt:
    case Hexagon::JMPrett:
    case Hexagon::JMPrettnew:
    case Hexagon::JMPrettnewpt: {
      // op: src
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 8;
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::J2_jump_extf:
    case Hexagon::J2_jump_extfnew:
    case Hexagon::J2_jump_extfnewpt:
    case Hexagon::J2_jump_extt:
    case Hexagon::J2_jump_exttnew:
    case Hexagon::J2_jump_exttnewpt:
    case Hexagon::J2_jump_noextf:
    case Hexagon::J2_jump_noextfnew:
    case Hexagon::J2_jump_noextfnewpt:
    case Hexagon::J2_jump_noextt:
    case Hexagon::J2_jump_noexttnew:
    case Hexagon::J2_jump_noexttnewpt:
    case Hexagon::J2_jumpf:
    case Hexagon::J2_jumpfnew:
    case Hexagon::J2_jumpfnewpt:
    case Hexagon::J2_jumpt:
    case Hexagon::J2_jumptnew:
    case Hexagon::J2_jumptnewpt: {
      // op: src
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 8;
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(98304)) << 7;
      Value |= (op & UINT64_C(31744)) << 6;
      Value |= (op & UINT64_C(512)) << 4;
      Value |= (op & UINT64_C(508)) >> 1;
      break;
    }
    case Hexagon::V6_vS32Ub_npred_ai_128B:
    case Hexagon::V6_vS32Ub_pred_ai_128B:
    case Hexagon::V6_vS32b_npred_ai_128B:
    case Hexagon::V6_vS32b_nqpred_ai_128B:
    case Hexagon::V6_vS32b_nt_npred_ai_128B:
    case Hexagon::V6_vS32b_nt_nqpred_ai_128B:
    case Hexagon::V6_vS32b_nt_pred_ai_128B:
    case Hexagon::V6_vS32b_nt_qpred_ai_128B:
    case Hexagon::V6_vS32b_pred_ai_128B:
    case Hexagon::V6_vS32b_qpred_ai_128B: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 11;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(1024)) << 3;
      Value |= (op & UINT64_C(896)) << 1;
      // op: src4
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= op & UINT64_C(31);
      break;
    }
    case Hexagon::V6_vS32b_new_npred_ai_128B:
    case Hexagon::V6_vS32b_new_pred_ai_128B:
    case Hexagon::V6_vS32b_nt_new_npred_ai_128B:
    case Hexagon::V6_vS32b_nt_new_pred_ai_128B: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 11;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(1024)) << 3;
      Value |= (op & UINT64_C(896)) << 1;
      // op: src4
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= op & UINT64_C(7);
      break;
    }
    case Hexagon::V6_vS32Ub_npred_ai:
    case Hexagon::V6_vS32Ub_pred_ai:
    case Hexagon::V6_vS32b_npred_ai:
    case Hexagon::V6_vS32b_nqpred_ai:
    case Hexagon::V6_vS32b_nt_npred_ai:
    case Hexagon::V6_vS32b_nt_nqpred_ai:
    case Hexagon::V6_vS32b_nt_pred_ai:
    case Hexagon::V6_vS32b_nt_qpred_ai:
    case Hexagon::V6_vS32b_pred_ai:
    case Hexagon::V6_vS32b_qpred_ai: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 11;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(512)) << 4;
      Value |= (op & UINT64_C(448)) << 2;
      // op: src4
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= op & UINT64_C(31);
      break;
    }
    case Hexagon::V6_vS32b_new_npred_ai:
    case Hexagon::V6_vS32b_new_pred_ai:
    case Hexagon::V6_vS32b_nt_new_npred_ai:
    case Hexagon::V6_vS32b_nt_new_pred_ai: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 11;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(512)) << 4;
      Value |= (op & UINT64_C(448)) << 2;
      // op: src4
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= op & UINT64_C(7);
      break;
    }
    case Hexagon::V6_vhistq: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 22;
      break;
    }
    case Hexagon::Y5_l2unlocka: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::V6_vS32Ub_ai_128B:
    case Hexagon::V6_vS32b_ai_128B:
    case Hexagon::V6_vS32b_nt_ai_128B: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(1024)) << 3;
      Value |= (op & UINT64_C(896)) << 1;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= op & UINT64_C(31);
      break;
    }
    case Hexagon::V6_vS32b_new_ai_128B:
    case Hexagon::V6_vS32b_nt_new_ai_128B: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(1024)) << 3;
      Value |= (op & UINT64_C(896)) << 1;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= op & UINT64_C(7);
      break;
    }
    case Hexagon::S2_storerd_io: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(12288)) << 13;
      Value |= (op & UINT64_C(2048)) << 2;
      Value |= (op & UINT64_C(2040)) >> 3;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S2_storerb_io: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(1536)) << 16;
      Value |= (op & UINT64_C(256)) << 5;
      Value |= op & UINT64_C(255);
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S2_storerbnew_io: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(1536)) << 16;
      Value |= (op & UINT64_C(256)) << 5;
      Value |= op & UINT64_C(255);
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 8;
      break;
    }
    case Hexagon::S4_storerb_ur:
    case Hexagon::S4_storerd_ur:
    case Hexagon::S4_storerf_ur:
    case Hexagon::S4_storerh_ur:
    case Hexagon::S4_storeri_ur: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(2)) << 12;
      Value |= (op & UINT64_C(1)) << 6;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= op & UINT64_C(63);
      // op: src4
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S4_storerbnew_ur:
    case Hexagon::S4_storerhnew_ur:
    case Hexagon::S4_storerinew_ur: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(2)) << 12;
      Value |= (op & UINT64_C(1)) << 6;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= op & UINT64_C(63);
      // op: src4
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 8;
      break;
    }
    case Hexagon::S2_storerf_io:
    case Hexagon::S2_storerh_io: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3072)) << 15;
      Value |= (op & UINT64_C(512)) << 4;
      Value |= (op & UINT64_C(510)) >> 1;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S2_storerhnew_io: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3072)) << 15;
      Value |= (op & UINT64_C(512)) << 4;
      Value |= (op & UINT64_C(510)) >> 1;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 8;
      break;
    }
    case Hexagon::V6_vS32Ub_ai:
    case Hexagon::V6_vS32b_ai:
    case Hexagon::V6_vS32b_nt_ai: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(512)) << 4;
      Value |= (op & UINT64_C(448)) << 2;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= op & UINT64_C(31);
      break;
    }
    case Hexagon::V6_vS32b_new_ai:
    case Hexagon::V6_vS32b_nt_new_ai: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(512)) << 4;
      Value |= (op & UINT64_C(448)) << 2;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= op & UINT64_C(7);
      break;
    }
    case Hexagon::S2_storeri_io: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(6144)) << 14;
      Value |= (op & UINT64_C(1024)) << 3;
      Value |= (op & UINT64_C(1020)) >> 2;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S2_storerinew_io: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(6144)) << 14;
      Value |= (op & UINT64_C(1024)) << 3;
      Value |= (op & UINT64_C(1020)) >> 2;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 8;
      break;
    }
    case Hexagon::Y6_l2gcleaninvpa:
    case Hexagon::Y6_l2gcleanpa: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
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
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(1536)) << 11;
      Value |= (op & UINT64_C(508)) >> 1;
      break;
    }
    case Hexagon::J4_cmpeqn1_f_jumpnv_nt:
    case Hexagon::J4_cmpeqn1_f_jumpnv_t:
    case Hexagon::J4_cmpeqn1_t_jumpnv_nt:
    case Hexagon::J4_cmpeqn1_t_jumpnv_t:
    case Hexagon::J4_cmpgtn1_f_jumpnv_nt:
    case Hexagon::J4_cmpgtn1_f_jumpnv_t:
    case Hexagon::J4_cmpgtn1_t_jumpnv_nt:
    case Hexagon::J4_cmpgtn1_t_jumpnv_t:
    case Hexagon::J4_tstbit0_f_jumpnv_nt:
    case Hexagon::J4_tstbit0_f_jumpnv_t:
    case Hexagon::J4_tstbit0_t_jumpnv_nt:
    case Hexagon::J4_tstbit0_t_jumpnv_t: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(1536)) << 11;
      Value |= (op & UINT64_C(508)) >> 1;
      break;
    }
    case Hexagon::J4_cmpeq_f_jumpnv_nt:
    case Hexagon::J4_cmpeq_f_jumpnv_t:
    case Hexagon::J4_cmpeq_t_jumpnv_nt:
    case Hexagon::J4_cmpeq_t_jumpnv_t:
    case Hexagon::J4_cmpeqi_f_jumpnv_nt:
    case Hexagon::J4_cmpeqi_f_jumpnv_t:
    case Hexagon::J4_cmpeqi_t_jumpnv_nt:
    case Hexagon::J4_cmpeqi_t_jumpnv_t:
    case Hexagon::J4_cmpgt_f_jumpnv_nt:
    case Hexagon::J4_cmpgt_f_jumpnv_t:
    case Hexagon::J4_cmpgt_t_jumpnv_nt:
    case Hexagon::J4_cmpgt_t_jumpnv_t:
    case Hexagon::J4_cmpgti_f_jumpnv_nt:
    case Hexagon::J4_cmpgti_f_jumpnv_t:
    case Hexagon::J4_cmpgti_t_jumpnv_nt:
    case Hexagon::J4_cmpgti_t_jumpnv_t:
    case Hexagon::J4_cmpgtu_f_jumpnv_nt:
    case Hexagon::J4_cmpgtu_f_jumpnv_t:
    case Hexagon::J4_cmpgtu_t_jumpnv_nt:
    case Hexagon::J4_cmpgtu_t_jumpnv_t:
    case Hexagon::J4_cmpgtui_f_jumpnv_nt:
    case Hexagon::J4_cmpgtui_f_jumpnv_t:
    case Hexagon::J4_cmpgtui_t_jumpnv_nt:
    case Hexagon::J4_cmpgtui_t_jumpnv_t: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(1536)) << 11;
      Value |= (op & UINT64_C(508)) >> 1;
      break;
    }
    case Hexagon::S4_pstorerbf_abs:
    case Hexagon::S4_pstorerbfnew_abs:
    case Hexagon::S4_pstorerbt_abs:
    case Hexagon::S4_pstorerbtnew_abs:
    case Hexagon::S4_pstorerdf_abs:
    case Hexagon::S4_pstorerdfnew_abs:
    case Hexagon::S4_pstorerdt_abs:
    case Hexagon::S4_pstorerdtnew_abs:
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
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: absaddr
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(48)) << 12;
      Value |= (op & UINT64_C(15)) << 3;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
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
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: absaddr
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(48)) << 12;
      Value |= (op & UINT64_C(15)) << 3;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 8;
      break;
    }
    case Hexagon::S2_pstorerif_io:
    case Hexagon::S2_pstorerit_io:
    case Hexagon::S4_pstorerifnew_io:
    case Hexagon::S4_pstoreritnew_io: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(128)) << 6;
      Value |= (op & UINT64_C(124)) << 1;
      // op: src4
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S2_pstorerinewf_io:
    case Hexagon::S2_pstorerinewt_io:
    case Hexagon::S4_pstorerinewfnew_io:
    case Hexagon::S4_pstorerinewtnew_io: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(128)) << 6;
      Value |= (op & UINT64_C(124)) << 1;
      // op: src4
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 8;
      break;
    }
    case Hexagon::S2_pstorerdf_io:
    case Hexagon::S2_pstorerdt_io:
    case Hexagon::S4_pstorerdfnew_io:
    case Hexagon::S4_pstorerdtnew_io: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(256)) << 5;
      Value |= op & UINT64_C(248);
      // op: src4
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S2_pstorerbf_io:
    case Hexagon::S2_pstorerbt_io:
    case Hexagon::S4_pstorerbfnew_io:
    case Hexagon::S4_pstorerbtnew_io: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(32)) << 8;
      Value |= (op & UINT64_C(31)) << 3;
      // op: src4
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S2_pstorerbnewf_io:
    case Hexagon::S2_pstorerbnewt_io:
    case Hexagon::S4_pstorerbnewfnew_io:
    case Hexagon::S4_pstorerbnewtnew_io: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(32)) << 8;
      Value |= (op & UINT64_C(31)) << 3;
      // op: src4
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 8;
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
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(64)) << 7;
      Value |= (op & UINT64_C(62)) << 2;
      // op: src4
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S2_pstorerhnewf_io:
    case Hexagon::S2_pstorerhnewt_io:
    case Hexagon::S4_pstorerhnewfnew_io:
    case Hexagon::S4_pstorerhnewtnew_io: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(64)) << 7;
      Value |= (op & UINT64_C(62)) << 2;
      // op: src4
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 8;
      break;
    }
    case Hexagon::V6_vS32Ub_npred_ppu:
    case Hexagon::V6_vS32Ub_pred_ppu:
    case Hexagon::V6_vS32b_npred_ppu:
    case Hexagon::V6_vS32b_nqpred_ppu:
    case Hexagon::V6_vS32b_nt_npred_ppu:
    case Hexagon::V6_vS32b_nt_nqpred_ppu:
    case Hexagon::V6_vS32b_nt_pred_ppu:
    case Hexagon::V6_vS32b_nt_qpred_ppu:
    case Hexagon::V6_vS32b_pred_ppu:
    case Hexagon::V6_vS32b_qpred_ppu: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 11;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(1)) << 13;
      // op: src4
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= op & UINT64_C(31);
      break;
    }
    case Hexagon::V6_vS32b_new_npred_ppu:
    case Hexagon::V6_vS32b_new_pred_ppu:
    case Hexagon::V6_vS32b_nt_new_npred_ppu:
    case Hexagon::V6_vS32b_nt_new_pred_ppu: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 11;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(1)) << 13;
      // op: src4
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= op & UINT64_C(7);
      break;
    }
    case Hexagon::V6_vS32Ub_npred_pi:
    case Hexagon::V6_vS32Ub_pred_pi:
    case Hexagon::V6_vS32b_npred_pi:
    case Hexagon::V6_vS32b_nqpred_pi:
    case Hexagon::V6_vS32b_nt_npred_pi:
    case Hexagon::V6_vS32b_nt_nqpred_pi:
    case Hexagon::V6_vS32b_nt_pred_pi:
    case Hexagon::V6_vS32b_nt_qpred_pi:
    case Hexagon::V6_vS32b_pred_pi:
    case Hexagon::V6_vS32b_qpred_pi: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 11;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(448)) << 2;
      // op: src4
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= op & UINT64_C(31);
      break;
    }
    case Hexagon::V6_vS32b_new_npred_pi:
    case Hexagon::V6_vS32b_new_pred_pi:
    case Hexagon::V6_vS32b_nt_new_npred_pi:
    case Hexagon::V6_vS32b_nt_new_pred_pi: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 11;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(448)) << 2;
      // op: src4
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= op & UINT64_C(7);
      break;
    }
    case Hexagon::V6_vS32Ub_npred_pi_128B:
    case Hexagon::V6_vS32Ub_pred_pi_128B:
    case Hexagon::V6_vS32b_npred_pi_128B:
    case Hexagon::V6_vS32b_nqpred_pi_128B:
    case Hexagon::V6_vS32b_nt_npred_pi_128B:
    case Hexagon::V6_vS32b_nt_nqpred_pi_128B:
    case Hexagon::V6_vS32b_nt_pred_pi_128B:
    case Hexagon::V6_vS32b_nt_qpred_pi_128B:
    case Hexagon::V6_vS32b_pred_pi_128B:
    case Hexagon::V6_vS32b_qpred_pi_128B: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 11;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(896)) << 1;
      // op: src4
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= op & UINT64_C(31);
      break;
    }
    case Hexagon::V6_vS32b_new_npred_pi_128B:
    case Hexagon::V6_vS32b_new_pred_pi_128B:
    case Hexagon::V6_vS32b_nt_new_npred_pi_128B:
    case Hexagon::V6_vS32b_nt_new_pred_pi_128B: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 11;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(896)) << 1;
      // op: src4
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= op & UINT64_C(7);
      break;
    }
    case Hexagon::V6_vaddbnq:
    case Hexagon::V6_vaddbnq_128B:
    case Hexagon::V6_vaddbq:
    case Hexagon::V6_vaddbq_128B:
    case Hexagon::V6_vaddhnq:
    case Hexagon::V6_vaddhnq_128B:
    case Hexagon::V6_vaddhq:
    case Hexagon::V6_vaddhq_128B:
    case Hexagon::V6_vaddwnq:
    case Hexagon::V6_vaddwnq_128B:
    case Hexagon::V6_vaddwq:
    case Hexagon::V6_vaddwq_128B:
    case Hexagon::V6_vsubbnq:
    case Hexagon::V6_vsubbnq_128B:
    case Hexagon::V6_vsubbq:
    case Hexagon::V6_vsubbq_128B:
    case Hexagon::V6_vsubhnq:
    case Hexagon::V6_vsubhnq_128B:
    case Hexagon::V6_vsubhq:
    case Hexagon::V6_vsubhq_128B:
    case Hexagon::V6_vsubwnq:
    case Hexagon::V6_vsubwnq_128B:
    case Hexagon::V6_vsubwq:
    case Hexagon::V6_vsubwq_128B: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 22;
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::V6_vcmov:
    case Hexagon::V6_vcmov_128B:
    case Hexagon::V6_vncmov:
    case Hexagon::V6_vncmov_128B: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 5;
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::V6_vccombine:
    case Hexagon::V6_vccombine_128B:
    case Hexagon::V6_vnccombine:
    case Hexagon::V6_vnccombine_128B: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(3)) << 5;
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::S2_asl_i_vh:
    case Hexagon::S2_asr_i_vh:
    case Hexagon::S2_lsr_i_vh: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 8;
      break;
    }
    case Hexagon::S2_asl_i_vw:
    case Hexagon::S2_asr_i_vw:
    case Hexagon::S2_lsr_i_vw: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S2_asl_i_p:
    case Hexagon::S2_asr_i_p:
    case Hexagon::S2_asr_i_p_rnd:
    case Hexagon::S2_lsr_i_p: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: dst
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(63)) << 8;
      break;
    }
    case Hexagon::S2_storerb_pr:
    case Hexagon::S2_storerd_pr:
    case Hexagon::S2_storerf_pr:
    case Hexagon::S2_storerh_pr:
    case Hexagon::S2_storeri_pr: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(1)) << 13;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S2_storerbnew_pr:
    case Hexagon::S2_storerhnew_pr:
    case Hexagon::S2_storerinew_pr: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(1)) << 13;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 8;
      break;
    }
    case Hexagon::V6_vS32Ub_ppu:
    case Hexagon::V6_vS32b_nt_ppu:
    case Hexagon::V6_vS32b_ppu: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(1)) << 13;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= op & UINT64_C(31);
      break;
    }
    case Hexagon::V6_vS32b_new_ppu:
    case Hexagon::V6_vS32b_nt_new_ppu: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(1)) << 13;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= op & UINT64_C(7);
      break;
    }
    case Hexagon::V6_vS32Ub_pi:
    case Hexagon::V6_vS32b_nt_pi:
    case Hexagon::V6_vS32b_pi: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(448)) << 2;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= op & UINT64_C(31);
      break;
    }
    case Hexagon::V6_vS32b_new_pi:
    case Hexagon::V6_vS32b_nt_new_pi: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(448)) << 2;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= op & UINT64_C(7);
      break;
    }
    case Hexagon::V6_vS32Ub_pi_128B:
    case Hexagon::V6_vS32b_nt_pi_128B:
    case Hexagon::V6_vS32b_pi_128B: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(896)) << 1;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= op & UINT64_C(31);
      break;
    }
    case Hexagon::V6_vS32b_new_pi_128B:
    case Hexagon::V6_vS32b_nt_new_pi_128B: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(896)) << 1;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= op & UINT64_C(7);
      break;
    }
    case Hexagon::S2_storerb_pi: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 3;
      break;
    }
    case Hexagon::S2_storerf_pi:
    case Hexagon::S2_storerh_pi: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(30)) << 2;
      break;
    }
    case Hexagon::S2_storeri_pi: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(60)) << 1;
      break;
    }
    case Hexagon::S2_storerd_pi: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= op & UINT64_C(120);
      break;
    }
    case Hexagon::S2_storerbnew_pi: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 8;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 3;
      break;
    }
    case Hexagon::S2_storerhnew_pi: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 8;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(30)) << 2;
      break;
    }
    case Hexagon::S2_storerinew_pi: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 8;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(60)) << 1;
      break;
    }
    case Hexagon::S2_pstorerbf_pi:
    case Hexagon::S2_pstorerbfnew_pi:
    case Hexagon::S2_pstorerbt_pi:
    case Hexagon::S2_pstorerbtnew_pi: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 3;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
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
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(30)) << 2;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S2_pstorerif_pi:
    case Hexagon::S2_pstorerifnew_pi:
    case Hexagon::S2_pstorerit_pi:
    case Hexagon::S2_pstoreritnew_pi: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(60)) << 1;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S2_pstorerdf_pi:
    case Hexagon::S2_pstorerdfnew_pi:
    case Hexagon::S2_pstorerdt_pi:
    case Hexagon::S2_pstorerdtnew_pi: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= op & UINT64_C(120);
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      break;
    }
    case Hexagon::S2_pstorerbnewf_pi:
    case Hexagon::S2_pstorerbnewfnew_pi:
    case Hexagon::S2_pstorerbnewt_pi:
    case Hexagon::S2_pstorerbnewtnew_pi: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 8;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(15)) << 3;
      break;
    }
    case Hexagon::S2_pstorerhnewf_pi:
    case Hexagon::S2_pstorerhnewfnew_pi:
    case Hexagon::S2_pstorerhnewt_pi:
    case Hexagon::S2_pstorerhnewtnew_pi: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 8;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(30)) << 2;
      break;
    }
    case Hexagon::S2_pstorerinewf_pi:
    case Hexagon::S2_pstorerinewfnew_pi:
    case Hexagon::S2_pstorerinewt_pi:
    case Hexagon::S2_pstorerinewtnew_pi: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= op & UINT64_C(3);
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(7)) << 8;
      // op: offset
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= (op & UINT64_C(60)) << 1;
      break;
    }
    case Hexagon::V6_vdeal:
    case Hexagon::V6_vdeal_128B:
    case Hexagon::V6_vshuff:
    case Hexagon::V6_vshuff_128B: {
      // op: src1
      op = getMachineOpValue(MI, MI.getOperand(2), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 8;
      // op: src2
      op = getMachineOpValue(MI, MI.getOperand(3), Fixups, STI);
      Value |= op & UINT64_C(31);
      // op: src3
      op = getMachineOpValue(MI, MI.getOperand(4), Fixups, STI);
      Value |= (op & UINT64_C(31)) << 16;
      break;
    }
    case Hexagon::S2_allocframe: {
      // op: u11_3
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(16376)) >> 3;
      break;
    }
    case Hexagon::V4_SS2_storew_sp: {
      // op: u5_2
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(124)) << 2;
      // op: Rt
      op = getMachineOpValue(MI, MI.getOperand(1), Fixups, STI);
      Value |= op & UINT64_C(15);
      break;
    }
    case Hexagon::V4_SS2_allocframe: {
      // op: u5_3
      op = getMachineOpValue(MI, MI.getOperand(0), Fixups, STI);
      Value |= (op & UINT64_C(248)) << 1;
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

