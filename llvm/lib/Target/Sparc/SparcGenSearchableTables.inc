#ifdef GET_ASITagsList_DECL
const ASITag *lookupASITagByEncoding(uint8_t Encoding);
const ASITag *lookupASITagByAltName(StringRef AltName);
const ASITag *lookupASITagByName(StringRef Name);
StringRef getASITagStr(StringTable::Offset);
#endif

#ifdef GET_ASITagsList_IMPL
constexpr ASITag ASITagsList[] = {
  { 1 /* "ASI_N" */, 7 /* "ASI_NUCLEUS" */, 0x4 }, // 0
  { 19 /* "ASI_N_L" */, 27 /* "ASI_NUCLEUS_LITTLE" */, 0xC }, // 1
  { 46 /* "ASI_AIUP" */, 55 /* "ASI_AS_IF_USER_PRIMARY" */, 0x10 }, // 2
  { 78 /* "ASI_AIUS" */, 87 /* "ASI_AS_IF_USER_SECONDARY" */, 0x11 }, // 3
  { 112 /* "ASI_AIUP_L" */, 123 /* "ASI_AS_IF_USER_PRIMARY_LITTLE" */, 0x18 }, // 4
  { 153 /* "ASI_AIUS_L" */, 164 /* "ASI_AS_IF_USER_SECONDARY_LITTLE" */, 0x19 }, // 5
  { 196 /* "ASI_P" */, 202 /* "ASI_PRIMARY" */, 0x80 }, // 6
  { 214 /* "ASI_S" */, 220 /* "ASI_SECONDARY" */, 0x81 }, // 7
  { 234 /* "ASI_PNF" */, 242 /* "ASI_PRIMARY_NOFAULT" */, 0x82 }, // 8
  { 262 /* "ASI_SNF" */, 270 /* "ASI_SECONDARY_NOFAULT" */, 0x83 }, // 9
  { 292 /* "ASI_P_L" */, 300 /* "ASI_PRIMARY_LITTLE" */, 0x88 }, // 10
  { 319 /* "ASI_S_L" */, 327 /* "ASI_SECONDARY_LITTLE" */, 0x89 }, // 11
  { 348 /* "ASI_PNF_L" */, 358 /* "ASI_PRIMARY_NOFAULT_LITTLE" */, 0x8A }, // 12
  { 385 /* "ASI_SNF_L" */, 395 /* "ASI_SECONDARY_NOFAULT_LITTLE" */, 0x8B }, // 13
 };

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
static constexpr char ASITagsListStringsStorage[] =
  "\0"
  "ASI_N\0"
  "ASI_NUCLEUS\0"
  "ASI_N_L\0"
  "ASI_NUCLEUS_LITTLE\0"
  "ASI_AIUP\0"
  "ASI_AS_IF_USER_PRIMARY\0"
  "ASI_AIUS\0"
  "ASI_AS_IF_USER_SECONDARY\0"
  "ASI_AIUP_L\0"
  "ASI_AS_IF_USER_PRIMARY_LITTLE\0"
  "ASI_AIUS_L\0"
  "ASI_AS_IF_USER_SECONDARY_LITTLE\0"
  "ASI_P\0"
  "ASI_PRIMARY\0"
  "ASI_S\0"
  "ASI_SECONDARY\0"
  "ASI_PNF\0"
  "ASI_PRIMARY_NOFAULT\0"
  "ASI_SNF\0"
  "ASI_SECONDARY_NOFAULT\0"
  "ASI_P_L\0"
  "ASI_PRIMARY_LITTLE\0"
  "ASI_S_L\0"
  "ASI_SECONDARY_LITTLE\0"
  "ASI_PNF_L\0"
  "ASI_PRIMARY_NOFAULT_LITTLE\0"
  "ASI_SNF_L\0"
  "ASI_SECONDARY_NOFAULT_LITTLE\0"
  ;
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

static constexpr llvm_ks::StringTable
ASITagsListStrings = ASITagsListStringsStorage;

StringRef getASITagStr(StringTable::Offset Offset) {
  return ASITagsListStrings[Offset];
}

const ASITag *lookupASITagByEncoding(uint8_t Encoding) {
  struct KeyType {
    uint8_t Encoding;
  };
  KeyType Key = {Encoding};
  struct Comp {
    bool operator()(const ASITag &LHS, const KeyType &RHS) const {
      if (LHS.Encoding < RHS.Encoding)
        return true;
      if (LHS.Encoding > RHS.Encoding)
        return false;
      return false;
    }
  };
  auto Table = ArrayRef(ASITagsList);
  auto Idx = std::lower_bound(Table.begin(), Table.end(), Key, Comp());
  if (Idx == Table.end() ||
      Key.Encoding != Idx->Encoding)
    return nullptr;

  return &*Idx;
}

const ASITag *lookupASITagByAltName(StringRef AltName) {
  struct IndexType {
    unsigned AltName;
    unsigned _index;
  };
  static const struct IndexType Index[] = {
    { 55 /* "ASI_AS_IF_USER_PRIMARY" */, 2 },
    { 123 /* "ASI_AS_IF_USER_PRIMARY_LITTLE" */, 4 },
    { 87 /* "ASI_AS_IF_USER_SECONDARY" */, 3 },
    { 164 /* "ASI_AS_IF_USER_SECONDARY_LITTLE" */, 5 },
    { 7 /* "ASI_NUCLEUS" */, 0 },
    { 27 /* "ASI_NUCLEUS_LITTLE" */, 1 },
    { 202 /* "ASI_PRIMARY" */, 6 },
    { 300 /* "ASI_PRIMARY_LITTLE" */, 10 },
    { 242 /* "ASI_PRIMARY_NOFAULT" */, 8 },
    { 358 /* "ASI_PRIMARY_NOFAULT_LITTLE" */, 12 },
    { 220 /* "ASI_SECONDARY" */, 7 },
    { 327 /* "ASI_SECONDARY_LITTLE" */, 11 },
    { 270 /* "ASI_SECONDARY_NOFAULT" */, 9 },
    { 395 /* "ASI_SECONDARY_NOFAULT_LITTLE" */, 13 },
  };

  struct KeyType {
    std::string AltName;
  };
  KeyType Key = {AltName.upper()};
  struct Comp {
    bool operator()(const IndexType &LHS, const KeyType &RHS) const {
      StringRef LHSAltNameStr = ASITagsListStrings[LHS.AltName];
      StringRef RHSAltNameStr = RHS.AltName;
      int CmpAltName = LHSAltNameStr.compare(RHSAltNameStr);
      if (CmpAltName < 0) return true;
      if (CmpAltName > 0) return false;
      return false;
    }
  };
  auto Table = ArrayRef(Index);
  auto Idx = std::lower_bound(Table.begin(), Table.end(), Key, Comp());
  if (Idx == Table.end() ||
      Key.AltName != ASITagsListStrings[Idx->AltName])
    return nullptr;

  return &ASITagsList[Idx->_index];
}

const ASITag *lookupASITagByName(StringRef Name) {
  struct IndexType {
    unsigned Name;
    unsigned _index;
  };
  static const struct IndexType Index[] = {
    { 46 /* "ASI_AIUP" */, 2 },
    { 112 /* "ASI_AIUP_L" */, 4 },
    { 78 /* "ASI_AIUS" */, 3 },
    { 153 /* "ASI_AIUS_L" */, 5 },
    { 1 /* "ASI_N" */, 0 },
    { 19 /* "ASI_N_L" */, 1 },
    { 196 /* "ASI_P" */, 6 },
    { 234 /* "ASI_PNF" */, 8 },
    { 348 /* "ASI_PNF_L" */, 12 },
    { 292 /* "ASI_P_L" */, 10 },
    { 214 /* "ASI_S" */, 7 },
    { 262 /* "ASI_SNF" */, 9 },
    { 385 /* "ASI_SNF_L" */, 13 },
    { 319 /* "ASI_S_L" */, 11 },
  };

  struct KeyType {
    std::string Name;
  };
  KeyType Key = {Name.upper()};
  struct Comp {
    bool operator()(const IndexType &LHS, const KeyType &RHS) const {
      StringRef LHSNameStr = ASITagsListStrings[LHS.Name];
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
      Key.Name != ASITagsListStrings[Idx->Name])
    return nullptr;

  return &ASITagsList[Idx->_index];
}
#endif

#ifdef GET_PrefetchTagsList_DECL
const PrefetchTag *lookupPrefetchTagByEncoding(uint8_t Encoding);
const PrefetchTag *lookupPrefetchTagByName(StringRef Name);
StringRef getPrefetchTagStr(StringTable::Offset);
#endif

#ifdef GET_PrefetchTagsList_IMPL
constexpr PrefetchTag PrefetchTagsList[] = {
  { 1 /* "n_reads" */, 0x0 }, // 0
  { 9 /* "one_read" */, 0x1 }, // 1
  { 18 /* "n_writes" */, 0x2 }, // 2
  { 27 /* "one_write" */, 0x3 }, // 3
  { 37 /* "page" */, 0x4 }, // 4
  { 42 /* "unified" */, 0x11 }, // 5
  { 50 /* "n_reads_strong" */, 0x14 }, // 6
  { 65 /* "one_read_strong" */, 0x15 }, // 7
  { 81 /* "n_writes_strong" */, 0x16 }, // 8
  { 97 /* "one_write_strong" */, 0x17 }, // 9
 };

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
static constexpr char PrefetchTagsListStringsStorage[] =
  "\0"
  "n_reads\0"
  "one_read\0"
  "n_writes\0"
  "one_write\0"
  "page\0"
  "unified\0"
  "n_reads_strong\0"
  "one_read_strong\0"
  "n_writes_strong\0"
  "one_write_strong\0"
  "N_READS\0"
  "N_READS_STRONG\0"
  "N_WRITES\0"
  "N_WRITES_STRONG\0"
  "ONE_READ\0"
  "ONE_READ_STRONG\0"
  "ONE_WRITE\0"
  "ONE_WRITE_STRONG\0"
  "PAGE\0"
  "UNIFIED\0"
  ;
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

static constexpr llvm_ks::StringTable
PrefetchTagsListStrings = PrefetchTagsListStringsStorage;

StringRef getPrefetchTagStr(StringTable::Offset Offset) {
  return PrefetchTagsListStrings[Offset];
}

const PrefetchTag *lookupPrefetchTagByEncoding(uint8_t Encoding) {
  struct KeyType {
    uint8_t Encoding;
  };
  KeyType Key = {Encoding};
  struct Comp {
    bool operator()(const PrefetchTag &LHS, const KeyType &RHS) const {
      if (LHS.Encoding < RHS.Encoding)
        return true;
      if (LHS.Encoding > RHS.Encoding)
        return false;
      return false;
    }
  };
  auto Table = ArrayRef(PrefetchTagsList);
  auto Idx = std::lower_bound(Table.begin(), Table.end(), Key, Comp());
  if (Idx == Table.end() ||
      Key.Encoding != Idx->Encoding)
    return nullptr;

  return &*Idx;
}

const PrefetchTag *lookupPrefetchTagByName(StringRef Name) {
  struct IndexType {
    unsigned Name;
    unsigned _index;
  };
  static const struct IndexType Index[] = {
    { 114 /* "N_READS" */, 0 },
    { 122 /* "N_READS_STRONG" */, 6 },
    { 137 /* "N_WRITES" */, 2 },
    { 146 /* "N_WRITES_STRONG" */, 8 },
    { 162 /* "ONE_READ" */, 1 },
    { 171 /* "ONE_READ_STRONG" */, 7 },
    { 187 /* "ONE_WRITE" */, 3 },
    { 197 /* "ONE_WRITE_STRONG" */, 9 },
    { 214 /* "PAGE" */, 4 },
    { 219 /* "UNIFIED" */, 5 },
  };

  struct KeyType {
    std::string Name;
  };
  KeyType Key = {Name.upper()};
  struct Comp {
    bool operator()(const IndexType &LHS, const KeyType &RHS) const {
      StringRef LHSNameStr = PrefetchTagsListStrings[LHS.Name];
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
      Key.Name != PrefetchTagsListStrings[Idx->Name])
    return nullptr;

  return &PrefetchTagsList[Idx->_index];
}
#endif

#undef GET_ASITagsList_DECL
#undef GET_ASITagsList_IMPL
#undef GET_PrefetchTagsList_DECL
#undef GET_PrefetchTagsList_IMPL
