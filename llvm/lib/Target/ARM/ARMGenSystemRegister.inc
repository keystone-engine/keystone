#ifdef GET_BankedRegsList_DECL
const BankedReg *lookupBankedRegByEncoding(uint8_t Encoding);
const BankedReg *lookupBankedRegByName(StringRef Name);
StringRef getBankedRegStr(StringTable::Offset);
#endif

#ifdef GET_BankedRegsList_IMPL
constexpr BankedReg BankedRegsList[] = {
  { 1 /* "r8_usr" */, 0x0 }, // 0
  { 8 /* "r9_usr" */, 0x1 }, // 1
  { 15 /* "r10_usr" */, 0x2 }, // 2
  { 23 /* "r11_usr" */, 0x3 }, // 3
  { 31 /* "r12_usr" */, 0x4 }, // 4
  { 39 /* "sp_usr" */, 0x5 }, // 5
  { 46 /* "lr_usr" */, 0x6 }, // 6
  { 53 /* "r8_fiq" */, 0x8 }, // 7
  { 60 /* "r9_fiq" */, 0x9 }, // 8
  { 67 /* "r10_fiq" */, 0xA }, // 9
  { 75 /* "r11_fiq" */, 0xB }, // 10
  { 83 /* "r12_fiq" */, 0xC }, // 11
  { 91 /* "sp_fiq" */, 0xD }, // 12
  { 98 /* "lr_fiq" */, 0xE }, // 13
  { 105 /* "lr_irq" */, 0x10 }, // 14
  { 112 /* "sp_irq" */, 0x11 }, // 15
  { 119 /* "lr_svc" */, 0x12 }, // 16
  { 126 /* "sp_svc" */, 0x13 }, // 17
  { 133 /* "lr_abt" */, 0x14 }, // 18
  { 140 /* "sp_abt" */, 0x15 }, // 19
  { 147 /* "lr_und" */, 0x16 }, // 20
  { 154 /* "sp_und" */, 0x17 }, // 21
  { 161 /* "lr_mon" */, 0x1C }, // 22
  { 168 /* "sp_mon" */, 0x1D }, // 23
  { 175 /* "elr_hyp" */, 0x1E }, // 24
  { 183 /* "sp_hyp" */, 0x1F }, // 25
  { 190 /* "spsr_fiq" */, 0x2E }, // 26
  { 199 /* "spsr_irq" */, 0x30 }, // 27
  { 208 /* "spsr_svc" */, 0x32 }, // 28
  { 217 /* "spsr_abt" */, 0x34 }, // 29
  { 226 /* "spsr_und" */, 0x36 }, // 30
  { 235 /* "spsr_mon" */, 0x3C }, // 31
  { 244 /* "spsr_hyp" */, 0x3E }, // 32
 };

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
static constexpr char BankedRegsListStringsStorage[] =
  "\0"
  "r8_usr\0"
  "r9_usr\0"
  "r10_usr\0"
  "r11_usr\0"
  "r12_usr\0"
  "sp_usr\0"
  "lr_usr\0"
  "r8_fiq\0"
  "r9_fiq\0"
  "r10_fiq\0"
  "r11_fiq\0"
  "r12_fiq\0"
  "sp_fiq\0"
  "lr_fiq\0"
  "lr_irq\0"
  "sp_irq\0"
  "lr_svc\0"
  "sp_svc\0"
  "lr_abt\0"
  "sp_abt\0"
  "lr_und\0"
  "sp_und\0"
  "lr_mon\0"
  "sp_mon\0"
  "elr_hyp\0"
  "sp_hyp\0"
  "spsr_fiq\0"
  "spsr_irq\0"
  "spsr_svc\0"
  "spsr_abt\0"
  "spsr_und\0"
  "spsr_mon\0"
  "spsr_hyp\0"
  "ELR_HYP\0"
  "LR_ABT\0"
  "LR_FIQ\0"
  "LR_IRQ\0"
  "LR_MON\0"
  "LR_SVC\0"
  "LR_UND\0"
  "LR_USR\0"
  "R10_FIQ\0"
  "R10_USR\0"
  "R11_FIQ\0"
  "R11_USR\0"
  "R12_FIQ\0"
  "R12_USR\0"
  "R8_FIQ\0"
  "R8_USR\0"
  "R9_FIQ\0"
  "R9_USR\0"
  "SPSR_ABT\0"
  "SPSR_FIQ\0"
  "SPSR_HYP\0"
  "SPSR_IRQ\0"
  "SPSR_MON\0"
  "SPSR_SVC\0"
  "SPSR_UND\0"
  "SP_ABT\0"
  "SP_FIQ\0"
  "SP_HYP\0"
  "SP_IRQ\0"
  "SP_MON\0"
  "SP_SVC\0"
  "SP_UND\0"
  "SP_USR\0"
  ;
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

static constexpr llvm_ks::StringTable
BankedRegsListStrings = BankedRegsListStringsStorage;

StringRef getBankedRegStr(StringTable::Offset Offset) {
  return BankedRegsListStrings[Offset];
}

const BankedReg *lookupBankedRegByEncoding(uint8_t Encoding) {
  struct KeyType {
    uint8_t Encoding;
  };
  KeyType Key = {Encoding};
  struct Comp {
    bool operator()(const BankedReg &LHS, const KeyType &RHS) const {
      if (LHS.Encoding < RHS.Encoding)
        return true;
      if (LHS.Encoding > RHS.Encoding)
        return false;
      return false;
    }
  };
  auto Table = ArrayRef(BankedRegsList);
  auto Idx = std::lower_bound(Table.begin(), Table.end(), Key, Comp());
  if (Idx == Table.end() ||
      Key.Encoding != Idx->Encoding)
    return nullptr;

  return &*Idx;
}

const BankedReg *lookupBankedRegByName(StringRef Name) {
  struct IndexType {
    unsigned Name;
    unsigned _index;
  };
  static const struct IndexType Index[] = {
    { 253 /* "ELR_HYP" */, 24 },
    { 261 /* "LR_ABT" */, 18 },
    { 268 /* "LR_FIQ" */, 13 },
    { 275 /* "LR_IRQ" */, 14 },
    { 282 /* "LR_MON" */, 22 },
    { 289 /* "LR_SVC" */, 16 },
    { 296 /* "LR_UND" */, 20 },
    { 303 /* "LR_USR" */, 6 },
    { 310 /* "R10_FIQ" */, 9 },
    { 318 /* "R10_USR" */, 2 },
    { 326 /* "R11_FIQ" */, 10 },
    { 334 /* "R11_USR" */, 3 },
    { 342 /* "R12_FIQ" */, 11 },
    { 350 /* "R12_USR" */, 4 },
    { 358 /* "R8_FIQ" */, 7 },
    { 365 /* "R8_USR" */, 0 },
    { 372 /* "R9_FIQ" */, 8 },
    { 379 /* "R9_USR" */, 1 },
    { 386 /* "SPSR_ABT" */, 29 },
    { 395 /* "SPSR_FIQ" */, 26 },
    { 404 /* "SPSR_HYP" */, 32 },
    { 413 /* "SPSR_IRQ" */, 27 },
    { 422 /* "SPSR_MON" */, 31 },
    { 431 /* "SPSR_SVC" */, 28 },
    { 440 /* "SPSR_UND" */, 30 },
    { 449 /* "SP_ABT" */, 19 },
    { 456 /* "SP_FIQ" */, 12 },
    { 463 /* "SP_HYP" */, 25 },
    { 470 /* "SP_IRQ" */, 15 },
    { 477 /* "SP_MON" */, 23 },
    { 484 /* "SP_SVC" */, 17 },
    { 491 /* "SP_UND" */, 21 },
    { 498 /* "SP_USR" */, 5 },
  };

  struct KeyType {
    std::string Name;
  };
  KeyType Key = {Name.upper()};
  struct Comp {
    bool operator()(const IndexType &LHS, const KeyType &RHS) const {
      StringRef LHSNameStr = BankedRegsListStrings[LHS.Name];
      StringRef RHSNameStr = RHS.Name;
      int CmpName = LHSNameStr.compare(RHSNameStr);
      if (CmpName < 0) return true;
      if (CmpName > 0) return false;
      return false;
    }
  };
  auto Table = ArrayRef(Index);
  auto Idx = std::lower_bound(Table.begin(), Table.end(), Key, Comp());
  if (Idx == Table.end() ||
      Key.Name != BankedRegsListStrings[Idx->Name])
    return nullptr;

  return &BankedRegsList[Idx->_index];
}
#endif

#ifdef GET_MClassSysRegsList_DECL
const MClassSysReg *lookupMClassSysRegByM1Encoding12(uint16_t M1Encoding12);
const MClassSysReg *lookupMClassSysRegByM2M3Encoding8(uint16_t M2M3Encoding8);
const MClassSysReg *lookupMClassSysRegByName(StringRef Name);
StringRef getMClassSysRegStr(StringTable::Offset);
#endif

#ifdef GET_MClassSysRegsList_IMPL
constexpr MClassSysReg MClassSysRegsList[] = {
  { 1 /* "apsr" */, 0x800, 0x100, 0x800,  {}  }, // 0
  { 6 /* "apsr_g" */, 0x400, 0x0, 0x400,  {ARM::FeatureDSP}  }, // 1
  { 13 /* "apsr_nzcvq" */, 0x1800, 0x200, 0x800,  {}  }, // 2
  { 24 /* "apsr_nzcvqg" */, 0xC00, 0x300, 0xC00,  {ARM::FeatureDSP}  }, // 3
  { 36 /* "basepri" */, 0x811, 0x111, 0x811,  {ARM::HasV7Ops}  }, // 4
  { 44 /* "basepri_max" */, 0x812, 0x112, 0x812,  {ARM::HasV7Ops}  }, // 5
  { 56 /* "basepri_ns" */, 0x891, 0x191, 0x891,  {ARM::Feature8MSecExt, ARM::HasV7Ops}  }, // 6
  { 67 /* "control" */, 0x814, 0x114, 0x814,  {}  }, // 7
  { 75 /* "control_ns" */, 0x894, 0x194, 0x894,  {ARM::Feature8MSecExt}  }, // 8
  { 86 /* "eapsr" */, 0x802, 0x102, 0x802,  {}  }, // 9
  { 92 /* "eapsr_g" */, 0x402, 0x2, 0x402,  {ARM::FeatureDSP}  }, // 10
  { 100 /* "eapsr_nzcvq" */, 0x1802, 0x202, 0x802,  {}  }, // 11
  { 112 /* "eapsr_nzcvqg" */, 0xC02, 0x302, 0xC02,  {ARM::FeatureDSP}  }, // 12
  { 125 /* "epsr" */, 0x806, 0x106, 0x806,  {}  }, // 13
  { 130 /* "faultmask" */, 0x813, 0x113, 0x813,  {ARM::HasV7Ops}  }, // 14
  { 140 /* "faultmask_ns" */, 0x893, 0x193, 0x893,  {ARM::Feature8MSecExt, ARM::HasV7Ops}  }, // 15
  { 153 /* "iapsr" */, 0x801, 0x101, 0x801,  {}  }, // 16
  { 159 /* "iapsr_g" */, 0x401, 0x1, 0x401,  {ARM::FeatureDSP}  }, // 17
  { 167 /* "iapsr_nzcvq" */, 0x1801, 0x201, 0x801,  {}  }, // 18
  { 179 /* "iapsr_nzcvqg" */, 0xC01, 0x301, 0xC01,  {ARM::FeatureDSP}  }, // 19
  { 192 /* "iepsr" */, 0x807, 0x107, 0x807,  {}  }, // 20
  { 198 /* "ipsr" */, 0x805, 0x105, 0x805,  {}  }, // 21
  { 203 /* "msp" */, 0x808, 0x108, 0x808,  {}  }, // 22
  { 207 /* "msplim" */, 0x80A, 0x10A, 0x80A,  {ARM::HasV8MBaselineOps}  }, // 23
  { 214 /* "msplim_ns" */, 0x88A, 0x18A, 0x88A,  {ARM::Feature8MSecExt, ARM::HasV8MBaselineOps}  }, // 24
  { 224 /* "msp_ns" */, 0x888, 0x188, 0x888,  {ARM::Feature8MSecExt}  }, // 25
  { 231 /* "pac_key_p_0" */, 0x820, 0x120, 0x820,  {ARM::FeaturePACBTI}  }, // 26
  { 243 /* "pac_key_p_0_ns" */, 0x8A0, 0x1A0, 0x8A0,  {ARM::FeaturePACBTI}  }, // 27
  { 258 /* "pac_key_p_1" */, 0x821, 0x121, 0x821,  {ARM::FeaturePACBTI}  }, // 28
  { 270 /* "pac_key_p_1_ns" */, 0x8A1, 0x1A1, 0x8A1,  {ARM::FeaturePACBTI}  }, // 29
  { 285 /* "pac_key_p_2" */, 0x822, 0x122, 0x822,  {ARM::FeaturePACBTI}  }, // 30
  { 297 /* "pac_key_p_2_ns" */, 0x8A2, 0x1A2, 0x8A2,  {ARM::FeaturePACBTI}  }, // 31
  { 312 /* "pac_key_p_3" */, 0x823, 0x123, 0x823,  {ARM::FeaturePACBTI}  }, // 32
  { 324 /* "pac_key_p_3_ns" */, 0x8A3, 0x1A3, 0x8A3,  {ARM::FeaturePACBTI}  }, // 33
  { 339 /* "pac_key_u_0" */, 0x824, 0x124, 0x824,  {ARM::FeaturePACBTI}  }, // 34
  { 351 /* "pac_key_u_0_ns" */, 0x8A4, 0x1A4, 0x8A4,  {ARM::FeaturePACBTI}  }, // 35
  { 366 /* "pac_key_u_1" */, 0x825, 0x125, 0x825,  {ARM::FeaturePACBTI}  }, // 36
  { 378 /* "pac_key_u_1_ns" */, 0x8A5, 0x1A5, 0x8A5,  {ARM::FeaturePACBTI}  }, // 37
  { 393 /* "pac_key_u_2" */, 0x826, 0x126, 0x826,  {ARM::FeaturePACBTI}  }, // 38
  { 405 /* "pac_key_u_2_ns" */, 0x8A6, 0x1A6, 0x8A6,  {ARM::FeaturePACBTI}  }, // 39
  { 420 /* "pac_key_u_3" */, 0x827, 0x127, 0x827,  {ARM::FeaturePACBTI}  }, // 40
  { 432 /* "pac_key_u_3_ns" */, 0x8A7, 0x1A7, 0x8A7,  {ARM::FeaturePACBTI}  }, // 41
  { 447 /* "primask" */, 0x810, 0x110, 0x810,  {}  }, // 42
  { 455 /* "primask_ns" */, 0x890, 0x190, 0x890,  {}  }, // 43
  { 466 /* "psp" */, 0x809, 0x109, 0x809,  {}  }, // 44
  { 470 /* "psplim" */, 0x80B, 0x10B, 0x80B,  {ARM::HasV8MBaselineOps}  }, // 45
  { 477 /* "psplim_ns" */, 0x88B, 0x18B, 0x88B,  {ARM::Feature8MSecExt, ARM::HasV8MBaselineOps}  }, // 46
  { 487 /* "psp_ns" */, 0x889, 0x189, 0x889,  {ARM::Feature8MSecExt}  }, // 47
  { 494 /* "sp_ns" */, 0x898, 0x198, 0x898,  {ARM::Feature8MSecExt}  }, // 48
  { 500 /* "xpsr" */, 0x803, 0x103, 0x803,  {}  }, // 49
  { 505 /* "xpsr_g" */, 0x403, 0x3, 0x403,  {ARM::FeatureDSP}  }, // 50
  { 512 /* "xpsr_nzcvq" */, 0x1803, 0x203, 0x803,  {}  }, // 51
  { 523 /* "xpsr_nzcvqg" */, 0xC03, 0x303, 0xC03,  {ARM::FeatureDSP}  }, // 52
 };

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
static constexpr char MClassSysRegsListStringsStorage[] =
  "\0"
  "apsr\0"
  "apsr_g\0"
  "apsr_nzcvq\0"
  "apsr_nzcvqg\0"
  "basepri\0"
  "basepri_max\0"
  "basepri_ns\0"
  "control\0"
  "control_ns\0"
  "eapsr\0"
  "eapsr_g\0"
  "eapsr_nzcvq\0"
  "eapsr_nzcvqg\0"
  "epsr\0"
  "faultmask\0"
  "faultmask_ns\0"
  "iapsr\0"
  "iapsr_g\0"
  "iapsr_nzcvq\0"
  "iapsr_nzcvqg\0"
  "iepsr\0"
  "ipsr\0"
  "msp\0"
  "msplim\0"
  "msplim_ns\0"
  "msp_ns\0"
  "pac_key_p_0\0"
  "pac_key_p_0_ns\0"
  "pac_key_p_1\0"
  "pac_key_p_1_ns\0"
  "pac_key_p_2\0"
  "pac_key_p_2_ns\0"
  "pac_key_p_3\0"
  "pac_key_p_3_ns\0"
  "pac_key_u_0\0"
  "pac_key_u_0_ns\0"
  "pac_key_u_1\0"
  "pac_key_u_1_ns\0"
  "pac_key_u_2\0"
  "pac_key_u_2_ns\0"
  "pac_key_u_3\0"
  "pac_key_u_3_ns\0"
  "primask\0"
  "primask_ns\0"
  "psp\0"
  "psplim\0"
  "psplim_ns\0"
  "psp_ns\0"
  "sp_ns\0"
  "xpsr\0"
  "xpsr_g\0"
  "xpsr_nzcvq\0"
  "xpsr_nzcvqg\0"
  "APSR\0"
  "APSR_G\0"
  "APSR_NZCVQ\0"
  "APSR_NZCVQG\0"
  "BASEPRI\0"
  "BASEPRI_MAX\0"
  "BASEPRI_NS\0"
  "CONTROL\0"
  "CONTROL_NS\0"
  "EAPSR\0"
  "EAPSR_G\0"
  "EAPSR_NZCVQ\0"
  "EAPSR_NZCVQG\0"
  "EPSR\0"
  "FAULTMASK\0"
  "FAULTMASK_NS\0"
  "IAPSR\0"
  "IAPSR_G\0"
  "IAPSR_NZCVQ\0"
  "IAPSR_NZCVQG\0"
  "IEPSR\0"
  "IPSR\0"
  "MSP\0"
  "MSPLIM\0"
  "MSPLIM_NS\0"
  "MSP_NS\0"
  "PAC_KEY_P_0\0"
  "PAC_KEY_P_0_NS\0"
  "PAC_KEY_P_1\0"
  "PAC_KEY_P_1_NS\0"
  "PAC_KEY_P_2\0"
  "PAC_KEY_P_2_NS\0"
  "PAC_KEY_P_3\0"
  "PAC_KEY_P_3_NS\0"
  "PAC_KEY_U_0\0"
  "PAC_KEY_U_0_NS\0"
  "PAC_KEY_U_1\0"
  "PAC_KEY_U_1_NS\0"
  "PAC_KEY_U_2\0"
  "PAC_KEY_U_2_NS\0"
  "PAC_KEY_U_3\0"
  "PAC_KEY_U_3_NS\0"
  "PRIMASK\0"
  "PRIMASK_NS\0"
  "PSP\0"
  "PSPLIM\0"
  "PSPLIM_NS\0"
  "PSP_NS\0"
  "SP_NS\0"
  "XPSR\0"
  "XPSR_G\0"
  "XPSR_NZCVQ\0"
  "XPSR_NZCVQG\0"
  ;
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

static constexpr llvm_ks::StringTable
MClassSysRegsListStrings = MClassSysRegsListStringsStorage;

StringRef getMClassSysRegStr(StringTable::Offset Offset) {
  return MClassSysRegsListStrings[Offset];
}

const MClassSysReg *lookupMClassSysRegByM1Encoding12(uint16_t M1Encoding12) {
  struct IndexType {
    uint16_t M1Encoding12;
    unsigned _index;
  };
  static const struct IndexType Index[] = {
    { 0x400, 1 },
    { 0x401, 17 },
    { 0x402, 10 },
    { 0x403, 50 },
    { 0x800, 0 },
    { 0x801, 16 },
    { 0x802, 9 },
    { 0x803, 49 },
    { 0x805, 21 },
    { 0x806, 13 },
    { 0x807, 20 },
    { 0x808, 22 },
    { 0x809, 44 },
    { 0x80A, 23 },
    { 0x80B, 45 },
    { 0x810, 42 },
    { 0x811, 4 },
    { 0x812, 5 },
    { 0x813, 14 },
    { 0x814, 7 },
    { 0x820, 26 },
    { 0x821, 28 },
    { 0x822, 30 },
    { 0x823, 32 },
    { 0x824, 34 },
    { 0x825, 36 },
    { 0x826, 38 },
    { 0x827, 40 },
    { 0x888, 25 },
    { 0x889, 47 },
    { 0x88A, 24 },
    { 0x88B, 46 },
    { 0x890, 43 },
    { 0x891, 6 },
    { 0x893, 15 },
    { 0x894, 8 },
    { 0x898, 48 },
    { 0x8A0, 27 },
    { 0x8A1, 29 },
    { 0x8A2, 31 },
    { 0x8A3, 33 },
    { 0x8A4, 35 },
    { 0x8A5, 37 },
    { 0x8A6, 39 },
    { 0x8A7, 41 },
    { 0xC00, 3 },
    { 0xC01, 19 },
    { 0xC02, 12 },
    { 0xC03, 52 },
    { 0x1800, 2 },
    { 0x1801, 18 },
    { 0x1802, 11 },
    { 0x1803, 51 },
  };

  struct KeyType {
    uint16_t M1Encoding12;
  };
  KeyType Key = {M1Encoding12};
  struct Comp {
    bool operator()(const IndexType &LHS, const KeyType &RHS) const {
      if (LHS.M1Encoding12 < RHS.M1Encoding12)
        return true;
      if (LHS.M1Encoding12 > RHS.M1Encoding12)
        return false;
      return false;
    }
  };
  auto Table = ArrayRef(Index);
  auto Idx = std::lower_bound(Table.begin(), Table.end(), Key, Comp());
  if (Idx == Table.end() ||
      Key.M1Encoding12 != Idx->M1Encoding12)
    return nullptr;

  return &MClassSysRegsList[Idx->_index];
}

const MClassSysReg *lookupMClassSysRegByM2M3Encoding8(uint16_t M2M3Encoding8) {
  struct IndexType {
    uint16_t M2M3Encoding8;
    unsigned _index;
  };
  static const struct IndexType Index[] = {
    { 0x0, 1 },
    { 0x1, 17 },
    { 0x2, 10 },
    { 0x3, 50 },
    { 0x100, 0 },
    { 0x101, 16 },
    { 0x102, 9 },
    { 0x103, 49 },
    { 0x105, 21 },
    { 0x106, 13 },
    { 0x107, 20 },
    { 0x108, 22 },
    { 0x109, 44 },
    { 0x10A, 23 },
    { 0x10B, 45 },
    { 0x110, 42 },
    { 0x111, 4 },
    { 0x112, 5 },
    { 0x113, 14 },
    { 0x114, 7 },
    { 0x120, 26 },
    { 0x121, 28 },
    { 0x122, 30 },
    { 0x123, 32 },
    { 0x124, 34 },
    { 0x125, 36 },
    { 0x126, 38 },
    { 0x127, 40 },
    { 0x188, 25 },
    { 0x189, 47 },
    { 0x18A, 24 },
    { 0x18B, 46 },
    { 0x190, 43 },
    { 0x191, 6 },
    { 0x193, 15 },
    { 0x194, 8 },
    { 0x198, 48 },
    { 0x1A0, 27 },
    { 0x1A1, 29 },
    { 0x1A2, 31 },
    { 0x1A3, 33 },
    { 0x1A4, 35 },
    { 0x1A5, 37 },
    { 0x1A6, 39 },
    { 0x1A7, 41 },
    { 0x200, 2 },
    { 0x201, 18 },
    { 0x202, 11 },
    { 0x203, 51 },
    { 0x300, 3 },
    { 0x301, 19 },
    { 0x302, 12 },
    { 0x303, 52 },
  };

  struct KeyType {
    uint16_t M2M3Encoding8;
  };
  KeyType Key = {M2M3Encoding8};
  struct Comp {
    bool operator()(const IndexType &LHS, const KeyType &RHS) const {
      if (LHS.M2M3Encoding8 < RHS.M2M3Encoding8)
        return true;
      if (LHS.M2M3Encoding8 > RHS.M2M3Encoding8)
        return false;
      return false;
    }
  };
  auto Table = ArrayRef(Index);
  auto Idx = std::lower_bound(Table.begin(), Table.end(), Key, Comp());
  if (Idx == Table.end() ||
      Key.M2M3Encoding8 != Idx->M2M3Encoding8)
    return nullptr;

  return &MClassSysRegsList[Idx->_index];
}

const MClassSysReg *lookupMClassSysRegByName(StringRef Name) {
  struct IndexType {
    unsigned Name;
    unsigned _index;
  };
  static const struct IndexType Index[] = {
    { 535 /* "APSR" */, 0 },
    { 540 /* "APSR_G" */, 1 },
    { 547 /* "APSR_NZCVQ" */, 2 },
    { 558 /* "APSR_NZCVQG" */, 3 },
    { 570 /* "BASEPRI" */, 4 },
    { 578 /* "BASEPRI_MAX" */, 5 },
    { 590 /* "BASEPRI_NS" */, 6 },
    { 601 /* "CONTROL" */, 7 },
    { 609 /* "CONTROL_NS" */, 8 },
    { 620 /* "EAPSR" */, 9 },
    { 626 /* "EAPSR_G" */, 10 },
    { 634 /* "EAPSR_NZCVQ" */, 11 },
    { 646 /* "EAPSR_NZCVQG" */, 12 },
    { 659 /* "EPSR" */, 13 },
    { 664 /* "FAULTMASK" */, 14 },
    { 674 /* "FAULTMASK_NS" */, 15 },
    { 687 /* "IAPSR" */, 16 },
    { 693 /* "IAPSR_G" */, 17 },
    { 701 /* "IAPSR_NZCVQ" */, 18 },
    { 713 /* "IAPSR_NZCVQG" */, 19 },
    { 726 /* "IEPSR" */, 20 },
    { 732 /* "IPSR" */, 21 },
    { 737 /* "MSP" */, 22 },
    { 741 /* "MSPLIM" */, 23 },
    { 748 /* "MSPLIM_NS" */, 24 },
    { 758 /* "MSP_NS" */, 25 },
    { 765 /* "PAC_KEY_P_0" */, 26 },
    { 777 /* "PAC_KEY_P_0_NS" */, 27 },
    { 792 /* "PAC_KEY_P_1" */, 28 },
    { 804 /* "PAC_KEY_P_1_NS" */, 29 },
    { 819 /* "PAC_KEY_P_2" */, 30 },
    { 831 /* "PAC_KEY_P_2_NS" */, 31 },
    { 846 /* "PAC_KEY_P_3" */, 32 },
    { 858 /* "PAC_KEY_P_3_NS" */, 33 },
    { 873 /* "PAC_KEY_U_0" */, 34 },
    { 885 /* "PAC_KEY_U_0_NS" */, 35 },
    { 900 /* "PAC_KEY_U_1" */, 36 },
    { 912 /* "PAC_KEY_U_1_NS" */, 37 },
    { 927 /* "PAC_KEY_U_2" */, 38 },
    { 939 /* "PAC_KEY_U_2_NS" */, 39 },
    { 954 /* "PAC_KEY_U_3" */, 40 },
    { 966 /* "PAC_KEY_U_3_NS" */, 41 },
    { 981 /* "PRIMASK" */, 42 },
    { 989 /* "PRIMASK_NS" */, 43 },
    { 1000 /* "PSP" */, 44 },
    { 1004 /* "PSPLIM" */, 45 },
    { 1011 /* "PSPLIM_NS" */, 46 },
    { 1021 /* "PSP_NS" */, 47 },
    { 1028 /* "SP_NS" */, 48 },
    { 1034 /* "XPSR" */, 49 },
    { 1039 /* "XPSR_G" */, 50 },
    { 1046 /* "XPSR_NZCVQ" */, 51 },
    { 1057 /* "XPSR_NZCVQG" */, 52 },
  };

  struct KeyType {
    std::string Name;
  };
  KeyType Key = {Name.upper()};
  struct Comp {
    bool operator()(const IndexType &LHS, const KeyType &RHS) const {
      StringRef LHSNameStr = MClassSysRegsListStrings[LHS.Name];
      StringRef RHSNameStr = RHS.Name;
      int CmpName = LHSNameStr.compare(RHSNameStr);
      if (CmpName < 0) return true;
      if (CmpName > 0) return false;
      return false;
    }
  };
  auto Table = ArrayRef(Index);
  auto Idx = std::lower_bound(Table.begin(), Table.end(), Key, Comp());
  if (Idx == Table.end() ||
      Key.Name != MClassSysRegsListStrings[Idx->Name])
    return nullptr;

  return &MClassSysRegsList[Idx->_index];
}
#endif

#undef GET_BankedRegsList_DECL
#undef GET_BankedRegsList_IMPL
#undef GET_MClassSysRegsList_DECL
#undef GET_MClassSysRegsList_IMPL
