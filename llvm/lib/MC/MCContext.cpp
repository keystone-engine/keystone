//===- lib/MC/MCContext.cpp - Machine Code Context ------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "llvm/MC/MCContext.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/Twine.h"
#include "llvm/MC/MCAssembler.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCCodeView.h"
#include "llvm/MC/MCDwarf.h"
#include "llvm/MC/MCLabel.h"
#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSectionELF.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCSymbolELF.h"
#include "llvm/Support/ELF.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SourceMgr.h"
#include <map>

using namespace llvm;

MCContext::MCContext(const MCAsmInfo *mai, const MCRegisterInfo *mri,
                     const MCObjectFileInfo *mofi, const SourceMgr *mgr,
                     bool DoAutoReset, uint64_t BaseAddr)
    : SrcMgr(mgr), MAI(mai), MRI(mri), MOFI(mofi), Allocator(),
      Symbols(Allocator), UsedNames(Allocator),
      CurrentDwarfLoc(0, 0, 0, DWARF2_FLAG_IS_STMT, 0, 0), DwarfLocSeen(false),
      GenDwarfForAssembly(false), GenDwarfFileNumber(0), DwarfVersion(4),
      AllowTemporaryLabels(true), DwarfCompileUnitID(0),
      AutoReset(DoAutoReset), HadError(false), BaseAddress(BaseAddr) {

  std::error_code EC = llvm::sys::fs::current_path(CompilationDir);
  if (EC)
    CompilationDir.clear();

  SecureLogFile = getenv("AS_SECURE_LOG_FILE");
  SecureLog = nullptr;
  SecureLogUsed = false;

  if (SrcMgr && SrcMgr->getNumBuffers())
    MainFileName =
        SrcMgr->getMemoryBuffer(SrcMgr->getMainFileID())->getBufferIdentifier();
}

MCContext::~MCContext() {
  if (AutoReset)
    reset();

  // NOTE: The symbols are all allocated out of a bump pointer allocator,
  // we don't need to free them here.
}

//===----------------------------------------------------------------------===//
// Module Lifetime Management
//===----------------------------------------------------------------------===//

void MCContext::reset() {
  // Call the destructors so the fragments are freed
  ELFAllocator.DestroyAll();

  MCSubtargetAllocator.DestroyAll();
  UsedNames.clear();
  Symbols.clear();
  SectionSymbols.clear();
  Allocator.Reset();
  Instances.clear();
  CompilationDir.clear();
  MainFileName.clear();
  MCDwarfLineTablesCUMap.clear();
  SectionsForRanges.clear();
  MCGenDwarfLabelEntries.clear();
  DwarfDebugFlags = StringRef();
  DwarfCompileUnitID = 0;
  CurrentDwarfLoc = MCDwarfLoc(0, 0, 0, DWARF2_FLAG_IS_STMT, 0, 0);

  ELFUniquingMap.clear();

  NextID.clear();
  AllowTemporaryLabels = true;
  DwarfLocSeen = false;
  GenDwarfForAssembly = false;
  GenDwarfFileNumber = 0;

  HadError = false;
}

//===----------------------------------------------------------------------===//
// Symbol Manipulation
//===----------------------------------------------------------------------===//

MCSymbol *MCContext::getOrCreateSymbol(const Twine &Name) {
  SmallString<128> NameSV;
  StringRef NameRef = Name.toStringRef(NameSV);

  assert(!NameRef.empty() && "Normal symbols cannot be unnamed!");

  MCSymbol *&Sym = Symbols[NameRef];
  if (!Sym)
    Sym = createSymbol(NameRef, false, false);

  return Sym;
}

MCSymbolELF *MCContext::getOrCreateSectionSymbol(const MCSectionELF &Section) {
  MCSymbolELF *&Sym = SectionSymbols[&Section];
  if (Sym)
    return Sym;

  StringRef Name = Section.getSectionName();

  MCSymbol *&OldSym = Symbols[Name];
  if (OldSym && OldSym->isUndefined()) {
    Sym = cast<MCSymbolELF>(OldSym);
    return Sym;
  }

  auto NameIter = UsedNames.insert(std::make_pair(Name, true)).first;
  Sym = new (&*NameIter, *this) MCSymbolELF(&*NameIter, /*isTemporary*/ false);

  if (!OldSym)
    OldSym = Sym;

  return Sym;
}

MCSymbol *MCContext::getOrCreateFrameAllocSymbol(StringRef FuncName,
                                                 unsigned Idx) {
  return getOrCreateSymbol(Twine(MAI->getPrivateGlobalPrefix()) + FuncName +
                           "$frame_escape_" + Twine(Idx));
}

MCSymbol *MCContext::getOrCreateParentFrameOffsetSymbol(StringRef FuncName) {
  return getOrCreateSymbol(Twine(MAI->getPrivateGlobalPrefix()) + FuncName +
                           "$parent_frame_offset");
}

MCSymbol *MCContext::getOrCreateLSDASymbol(StringRef FuncName) {
  return getOrCreateSymbol(Twine(MAI->getPrivateGlobalPrefix()) + "__ehtable$" +
                           FuncName);
}

MCSymbol *MCContext::createSymbolImpl(const StringMapEntry<bool> *Name,
                                      bool IsTemporary) {
  if (MOFI) {
    switch (MOFI->getObjectFileType()) {
    case MCObjectFileInfo::IsELF:
      return new (Name, *this) MCSymbolELF(Name, IsTemporary);
    }
  }
  return new (Name, *this) MCSymbol(MCSymbol::SymbolKindUnset, Name,
                                    IsTemporary);
}

MCSymbol *MCContext::createSymbol(StringRef Name, bool AlwaysAddSuffix,
                                  bool CanBeUnnamed) {
  if (CanBeUnnamed && !UseNamesOnTempLabels)
    return createSymbolImpl(nullptr, true);

  // Determine whether this is an user writter assembler temporary or normal
  // label, if used.
  bool IsTemporary = CanBeUnnamed;
  if (AllowTemporaryLabels && !IsTemporary)
    IsTemporary = Name.startswith(MAI->getPrivateGlobalPrefix());

  SmallString<128> NewName = Name;
  bool AddSuffix = AlwaysAddSuffix;
  unsigned &NextUniqueID = NextID[Name];
  for (;;) {
    if (AddSuffix) {
      NewName.resize(Name.size());
      raw_svector_ostream(NewName) << NextUniqueID++;
    }
    auto NameEntry = UsedNames.insert(std::make_pair(NewName, true));
    if (NameEntry.second) {
      // Ok, we found a name. Have the MCSymbol object itself refer to the copy
      // of the string that is embedded in the UsedNames entry.
      return createSymbolImpl(&*NameEntry.first, IsTemporary);
    }
    assert(IsTemporary && "Cannot rename non-temporary symbols");
    AddSuffix = true;
  }
  llvm_unreachable("Infinite loop");
}

MCSymbol *MCContext::createTempSymbol(const Twine &Name, bool AlwaysAddSuffix,
                                      bool CanBeUnnamed) {
  SmallString<128> NameSV;
  raw_svector_ostream(NameSV) << MAI->getPrivateGlobalPrefix() << Name;
  return createSymbol(NameSV, AlwaysAddSuffix, CanBeUnnamed);
}

MCSymbol *MCContext::createLinkerPrivateTempSymbol() {
  SmallString<128> NameSV;
  raw_svector_ostream(NameSV) << MAI->getLinkerPrivateGlobalPrefix() << "tmp";
  return createSymbol(NameSV, true, false);
}

MCSymbol *MCContext::createTempSymbol(bool CanBeUnnamed) {
  return createTempSymbol("tmp", true, CanBeUnnamed);
}

unsigned MCContext::NextInstance(unsigned LocalLabelVal) {
  MCLabel *&Label = Instances[LocalLabelVal];
  if (!Label)
    Label = new (*this) MCLabel(0);
  return Label->incInstance();
}

unsigned MCContext::GetInstance(unsigned LocalLabelVal) {
  MCLabel *&Label = Instances[LocalLabelVal];
  if (!Label)
    Label = new (*this) MCLabel(0);
  return Label->getInstance();
}

MCSymbol *MCContext::getOrCreateDirectionalLocalSymbol(unsigned LocalLabelVal,
                                                       unsigned Instance) {
  MCSymbol *&Sym = LocalSymbols[std::make_pair(LocalLabelVal, Instance)];
  if (!Sym)
    Sym = createTempSymbol(false);
  return Sym;
}

MCSymbol *MCContext::createDirectionalLocalSymbol(unsigned LocalLabelVal) {
  unsigned Instance = NextInstance(LocalLabelVal);
  return getOrCreateDirectionalLocalSymbol(LocalLabelVal, Instance);
}

MCSymbol *MCContext::getDirectionalLocalSymbol(unsigned LocalLabelVal,
                                               bool Before) {
  unsigned Instance = GetInstance(LocalLabelVal);
  if (!Before)
    ++Instance;
  return getOrCreateDirectionalLocalSymbol(LocalLabelVal, Instance);
}

MCSymbol *MCContext::lookupSymbol(const Twine &Name) const {
  SmallString<128> NameSV;
  StringRef NameRef = Name.toStringRef(NameSV);
  return Symbols.lookup(NameRef);
}

//===----------------------------------------------------------------------===//
// Section Management
//===----------------------------------------------------------------------===//

void MCContext::renameELFSection(MCSectionELF *Section, StringRef Name) {
  StringRef GroupName;
  if (const MCSymbol *Group = Section->getGroup())
    GroupName = Group->getName();

  unsigned UniqueID = Section->getUniqueID();
  ELFUniquingMap.erase(
      ELFSectionKey{Section->getSectionName(), GroupName, UniqueID});
  auto I = ELFUniquingMap.insert(std::make_pair(
                                     ELFSectionKey{Name, GroupName, UniqueID},
                                     Section))
               .first;
  StringRef CachedName = I->first.SectionName;
  const_cast<MCSectionELF *>(Section)->setSectionName(CachedName);
}

MCSectionELF *MCContext::createELFRelSection(StringRef Name, unsigned Type,
                                             unsigned Flags, unsigned EntrySize,
                                             const MCSymbolELF *Group,
                                             const MCSectionELF *Associated) {
  StringMap<bool>::iterator I;
  bool Inserted;
  std::tie(I, Inserted) = ELFRelSecNames.insert(std::make_pair(Name, true));

  return new (ELFAllocator.Allocate())
      MCSectionELF(I->getKey(), Type, Flags, SectionKind::getReadOnly(),
                   EntrySize, Group, true, nullptr, Associated);
}

MCSectionELF *MCContext::getELFSection(StringRef Section, unsigned Type,
                                       unsigned Flags, unsigned EntrySize,
                                       StringRef Group, unsigned UniqueID,
                                       const char *BeginSymName) {
  MCSymbolELF *GroupSym = nullptr;
  if (!Group.empty())
    GroupSym = cast<MCSymbolELF>(getOrCreateSymbol(Group));

  return getELFSection(Section, Type, Flags, EntrySize, GroupSym, UniqueID,
                       BeginSymName, nullptr);
}

MCSectionELF *MCContext::getELFSection(StringRef Section, unsigned Type,
                                       unsigned Flags, unsigned EntrySize,
                                       const MCSymbolELF *GroupSym,
                                       unsigned UniqueID,
                                       const char *BeginSymName,
                                       const MCSectionELF *Associated) {
  StringRef Group = "";
  if (GroupSym)
    Group = GroupSym->getName();
  // Do the lookup, if we have a hit, return it.
  auto IterBool = ELFUniquingMap.insert(
      std::make_pair(ELFSectionKey{Section, Group, UniqueID}, nullptr));
  auto &Entry = *IterBool.first;
  if (!IterBool.second)
    return Entry.second;

  StringRef CachedName = Entry.first.SectionName;

  SectionKind Kind;
  if (Flags & ELF::SHF_EXECINSTR)
    Kind = SectionKind::getText();
  else
    Kind = SectionKind::getReadOnly();

  MCSymbol *Begin = nullptr;
  if (BeginSymName)
    Begin = createTempSymbol(BeginSymName, false);

  MCSectionELF *Result = new (ELFAllocator.Allocate())
      MCSectionELF(CachedName, Type, Flags, Kind, EntrySize, GroupSym, UniqueID,
                   Begin, Associated);
  Entry.second = Result;
  return Result;
}

MCSectionELF *MCContext::createELFGroupSection(const MCSymbolELF *Group) {
  MCSectionELF *Result = new (ELFAllocator.Allocate())
      MCSectionELF(".group", ELF::SHT_GROUP, 0, SectionKind::getReadOnly(), 4,
                   Group, ~0, nullptr, nullptr);
  return Result;
}

MCSubtargetInfo &MCContext::getSubtargetCopy(const MCSubtargetInfo &STI) {
  return *new (MCSubtargetAllocator.Allocate()) MCSubtargetInfo(STI);
}

//===----------------------------------------------------------------------===//
// Dwarf Management
//===----------------------------------------------------------------------===//

/// getDwarfFile - takes a file name an number to place in the dwarf file and
/// directory tables.  If the file number has already been allocated it is an
/// error and zero is returned and the client reports the error, else the
/// allocated file number is returned.  The file numbers may be in any order.
unsigned MCContext::getDwarfFile(StringRef Directory, StringRef FileName,
                                 unsigned FileNumber, unsigned CUID) {
  return 0;
}

/// isValidDwarfFileNumber - takes a dwarf file number and returns true if it
/// currently is assigned and false otherwise.
bool MCContext::isValidDwarfFileNumber(unsigned FileNumber, unsigned CUID) {
  const SmallVectorImpl<MCDwarfFile> &MCDwarfFiles = getMCDwarfFiles(CUID);
  if (FileNumber == 0 || FileNumber >= MCDwarfFiles.size())
    return false;

  return !MCDwarfFiles[FileNumber].Name.empty();
}

/// Remove empty sections from SectionStartEndSyms, to avoid generating
/// useless debug info for them.
void MCContext::finalizeDwarfSections(MCStreamer &MCOS) {
  SectionsForRanges.remove_if(
      [&](MCSection *Sec) { return !MCOS.mayHaveInstructions(*Sec); });
}

unsigned MCContext::getCVFile(StringRef FileName, unsigned FileNumber) {
  return 0;
}

bool MCContext::isValidCVFileNumber(unsigned FileNumber) {
  return true;
}

//===----------------------------------------------------------------------===//
// Error Reporting
//===----------------------------------------------------------------------===//

void MCContext::reportError(SMLoc Loc, const Twine &Msg) {
  HadError = true;

  // If we have a source manager use it. Otherwise just use the generic
  // report_fatal_error().
  if (!SrcMgr)
    report_fatal_error(Msg, false);

  // Use the source manager to print the message.
  SrcMgr->PrintMessage(Loc, SourceMgr::DK_Error, Msg);
}

void MCContext::reportFatalError(SMLoc Loc, const Twine &Msg) {
  reportError(Loc, Msg);

  // If we reached here, we are failing ungracefully. Run the interrupt handlers
  // to make sure any special cleanups get done, in particular that we remove
  // files registered with RemoveFileOnSignal.
  // sys::RunInterruptHandlers();
  exit(1);
}
