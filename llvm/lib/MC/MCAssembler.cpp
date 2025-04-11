//===- lib/MC/MCAssembler.cpp - Assembler Backend Implementation ----------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "llvm/MC/MCAssembler.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/Twine.h"
#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCAsmLayout.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDwarf.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCFixupKindInfo.h"
#include "llvm/MC/MCObjectWriter.h"
#include "llvm/MC/MCSection.h"
#include "llvm/MC/MCSectionELF.h"
#include "llvm/MC/MCSymbol.h"
#include "llvm/MC/MCValue.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/LEB128.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/raw_ostream.h"
#include <tuple>

#include "keystone/keystone.h"

using namespace llvm_ks;

#define DEBUG_TYPE "assembler"

// FIXME FIXME FIXME: There are number of places in this file where we convert
// what is a 64-bit assembler value used for computation into a value in the
// object file, which may truncate it. We should detect that truncation where
// invalid and report errors back.

/* *** */

MCAssembler::MCAssembler(MCContext &Context_, MCAsmBackend &Backend_,
                         MCCodeEmitter &Emitter_, MCObjectWriter &Writer_)
    : Context(Context_), Backend(Backend_), Emitter(Emitter_), Writer(Writer_),
      BundleAlignSize(0), RelaxAll(false), SubsectionsViaSymbols(false),
      IncrementalLinkerCompatible(false), ELFHeaderEFlags(0) {
  VersionMinInfo.Major = 0; // Major version == 0 for "none specified"
}

MCAssembler::~MCAssembler() {
}

void MCAssembler::reset() {
  Sections.clear();
  Symbols.clear();
  IndirectSymbols.clear();
  DataRegions.clear();
  LinkerOptions.clear();
  FileNames.clear();
  ThumbFuncs.clear();
  BundleAlignSize = 0;
  RelaxAll = false;
  SubsectionsViaSymbols = false;
  IncrementalLinkerCompatible = false;
  ELFHeaderEFlags = 0;
  LOHContainer.reset();
  VersionMinInfo.Major = 0;

  // reset objects owned by us
  getBackend().reset();
  getEmitter().reset();
  getWriter().reset();
  getLOHContainer().reset();
}

bool MCAssembler::registerSection(MCSection &Section) {
  if (Section.isRegistered())
    return false;
  Sections.push_back(&Section);
  Section.setIsRegistered(true);
  return true;
}

bool MCAssembler::isThumbFunc(const MCSymbol *Symbol) const {
  if (ThumbFuncs.count(Symbol))
    return true;

  if (!Symbol->isVariable())
    return false;

  // FIXME: It looks like gas supports some cases of the form "foo + 2". It
  // is not clear if that is a bug or a feature.
  const MCExpr *Expr = Symbol->getVariableValue();
  const MCSymbolRefExpr *Ref = dyn_cast<MCSymbolRefExpr>(Expr);
  if (!Ref)
    return false;

  if (Ref->getKind() != MCSymbolRefExpr::VK_None)
    return false;

  const MCSymbol &Sym = Ref->getSymbol();
  if (!isThumbFunc(&Sym))
    return false;

  ThumbFuncs.insert(Symbol); // Cache it.
  return true;
}

bool MCAssembler::isSymbolLinkerVisible(const MCSymbol &Symbol) const {
  // Non-temporary labels should always be visible to the linker.
  if (!Symbol.isTemporary())
    return true;

  // Absolute temporary labels are never visible.
  if (!Symbol.isInSection())
    return false;

  if (Symbol.isUsedInReloc())
    return true;

  return false;
}

const MCSymbol *MCAssembler::getAtom(const MCSymbol &S) const {
  // Linker visible symbols define atoms.
  if (isSymbolLinkerVisible(S))
    return &S;

  // Absolute and undefined symbols have no defining atom.
  if (!S.isInSection())
    return nullptr;

  // Non-linker visible symbols in sections which can't be atomized have no
  // defining atom.
  if (!getContext().getAsmInfo()->isSectionAtomizableBySymbols(
          *S.getFragment()->getParent()))
    return nullptr;

  // Otherwise, return the atom for the containing fragment.
  return S.getFragment()->getAtom();
}

bool MCAssembler::evaluateFixup(const MCAsmLayout &Layout,
                                const MCFixup &Fixup, const MCFragment *DF,
                                MCValue &Target, uint64_t &Value, unsigned int &KsError) const
{
  KsError = 0;

  // FIXME: This code has some duplication with recordRelocation. We should
  // probably merge the two into a single callback that tries to evaluate a
  // fixup and records a relocation if one is needed.
  const MCExpr *Expr = Fixup.getValue();
  if (!Expr->evaluateAsRelocatable(Target, &Layout, &Fixup)) {
    // getContext().reportError(Fixup.getLoc(), "expected relocatable expression");
    // Claim to have completely evaluated the fixup, to prevent any further
    // processing from being done.
    // return true;
    Value = 0;
    KsError = KS_ERR_ASM_INVALIDOPERAND;
    return false;
  }

  bool IsPCRel = Backend.getFixupKindInfo(
    Fixup.getKind()).Flags & MCFixupKindInfo::FKF_IsPCRel;

  bool IsResolved;
  if (IsPCRel) {
    if (Target.getSymB()) {
      IsResolved = false;
    } else if (!Target.getSymA()) {
      if (getBackend().getArch() == KS_ARCH_X86)
          IsResolved = true;
      else
          IsResolved = false;
    } else {
      const MCSymbolRefExpr *A = Target.getSymA();
      const MCSymbol &SA = A->getSymbol();
      if (A->getKind() != MCSymbolRefExpr::VK_None || SA.isUndefined()) {
        IsResolved = false;
      } else {
        IsResolved = getWriter().isSymbolRefDifferenceFullyResolvedImpl(
            *this, SA, *DF, false, true);
      }
    }
  } else {
    IsResolved = Target.isAbsolute();
  }

  Value = Target.getConstant();

  if (const MCSymbolRefExpr *A = Target.getSymA()) {
    const MCSymbol &Sym = A->getSymbol();
    bool valid;
    if (Sym.isDefined()) {
      Value += Layout.getSymbolOffset(Sym, valid);
      if (!valid) {
        KsError = KS_ERR_ASM_FIXUP_INVALID;
        return false;
      }
    } else {
        // a missing symbol. is there any resolver registered?
        if (KsSymResolver) {
            uint64_t imm;
            ks_sym_resolver resolver = (ks_sym_resolver)KsSymResolver;
            if (resolver(Sym.getName().str().c_str(), &imm)) {
                // resolver handled this symbol
                Value += imm;
                IsResolved = true;
            } else {
                // resolver did not handle this symbol
                KsError = KS_ERR_ASM_SYMBOL_MISSING;
                return false;
            }
        } else {
            // no resolver registered
            KsError = KS_ERR_ASM_SYMBOL_MISSING;
            return false;
        }
    }
  }

  if (const MCSymbolRefExpr *B = Target.getSymB()) {
    const MCSymbol &Sym = B->getSymbol();
    bool valid;
    if (Sym.isDefined()) {
      Value -= Layout.getSymbolOffset(Sym, valid);
      if (!valid) {
        KsError = KS_ERR_ASM_FIXUP_INVALID;
        return false;
      }
    }
  }

  bool ShouldAlignPC = Backend.getFixupKindInfo(Fixup.getKind()).Flags &
                         MCFixupKindInfo::FKF_IsAlignedDownTo32Bits;
  assert((ShouldAlignPC ? IsPCRel : true) &&
    "FKF_IsAlignedDownTo32Bits is only allowed on PC-relative fixups!");

  if (IsPCRel) {
    bool valid;
    uint64_t Offset = Layout.getFragmentOffset(DF, valid) + Fixup.getOffset();
    if (!valid) {
        KsError = KS_ERR_ASM_FRAGMENT_INVALID;
        return false;
    }

    // A number of ARM fixups in Thumb mode require that the effective PC
    // address be determined as the 32-bit aligned version of the actual offset.
    if (ShouldAlignPC) Offset &= ~0x3;
    Value -= Offset;
  }

  // Let the backend adjust the fixup value if necessary, including whether
  // we need a relocation.
  Backend.processFixupValue(*this, Layout, Fixup, DF, Target, Value,
                            IsResolved);

  return IsResolved;
}

uint64_t MCAssembler::computeFragmentSize(const MCAsmLayout &Layout,
                                          const MCFragment &F, bool &valid) const
{
  valid = true;
  switch (F.getKind()) {
  case MCFragment::FT_Data:
    return cast<MCDataFragment>(F).getContents().size();
  case MCFragment::FT_Relaxable:
    return cast<MCRelaxableFragment>(F).getContents().size();
  case MCFragment::FT_CompactEncodedInst:
    return cast<MCCompactEncodedInstFragment>(F).getContents().size();
  case MCFragment::FT_Fill:
    return cast<MCFillFragment>(F).getSize();

  case MCFragment::FT_LEB:
    return cast<MCLEBFragment>(F).getContents().size();

  case MCFragment::FT_SafeSEH:
    return 4;

  case MCFragment::FT_Align: {
    const MCAlignFragment &AF = cast<MCAlignFragment>(F);
    unsigned Offset = Layout.getFragmentOffset(&AF, valid);
    if (!valid) {
        return 0;
    }
    unsigned Size = OffsetToAlignment(Offset, AF.getAlignment());
    // If we are padding with nops, force the padding to be larger than the
    // minimum nop size.
    if (Size > 0 && AF.hasEmitNops()) {
      while (Size % getBackend().getMinimumNopSize())
        Size += AF.getAlignment();
    }
    if (Size > AF.getMaxBytesToEmit())
      return 0;
    return Size;
  }

  case MCFragment::FT_Org: {
    const MCOrgFragment &OF = cast<MCOrgFragment>(F);
    MCValue Value;
    if (!OF.getOffset().evaluateAsValue(Value, Layout)) {
      //report_fatal_error("expected assembly-time absolute expression");
      valid = false;
      return 0;
    }

    // FIXME: We need a way to communicate this error.
    uint64_t FragmentOffset = Layout.getFragmentOffset(&OF, valid);
    if (!valid) {
      return 0;
    }
    int64_t TargetLocation = Value.getConstant();
    if (const MCSymbolRefExpr *A = Value.getSymA()) {
      uint64_t Val;
      if (!Layout.getSymbolOffset(A->getSymbol(), Val, valid)) {
        //report_fatal_error("expected absolute expression");
        valid = false;
        return 0;
      }
      TargetLocation += Val;
    }
    int64_t Size = TargetLocation - FragmentOffset;
    if (Size < 0 || Size >= 0x40000000) {
      //report_fatal_error("invalid .org offset '" + Twine(TargetLocation) +
      //                   "' (at offset '" + Twine(FragmentOffset) + "')");
      valid = false;
      return 0;
    }
    return Size;
  }

  case MCFragment::FT_Dwarf:
    return cast<MCDwarfLineAddrFragment>(F).getContents().size();
  case MCFragment::FT_DwarfFrame:
    return cast<MCDwarfCallFrameFragment>(F).getContents().size();
  case MCFragment::FT_Dummy:
    llvm_unreachable("Should not have been added");
  }

  llvm_unreachable("invalid fragment kind");
}

bool MCAsmLayout::layoutFragment(MCFragment *F)
{
  MCFragment *Prev = F->getPrevNode();

  // We should never try to recompute something which is valid.
  //assert(!isFragmentValid(F) && "Attempt to recompute a valid fragment!");
  if (isFragmentValid(F))
      return true;

  // We should never try to compute the fragment layout if its predecessor
  // isn't valid.
  //assert((!Prev || isFragmentValid(Prev)) &&
  //       "Attempt to compute fragment before its predecessor!");
  if (Prev && !isFragmentValid(Prev))
      return true;

  bool valid = true;
  // Compute fragment offset and size.
  if (Prev)
    F->Offset = Prev->Offset + getAssembler().computeFragmentSize(*this, *Prev, valid);
  else
    F->Offset = getAssembler().getContext().getBaseAddress();
  if (!valid) {
      return false;
  }
  LastValidFragment[F->getParent()] = F;

  // If bundling is enabled and this fragment has instructions in it, it has to
  // obey the bundling restrictions. With padding, we'll have:
  //
  //
  //        BundlePadding
  //             |||
  // -------------------------------------
  //   Prev  |##########|       F        |
  // -------------------------------------
  //                    ^
  //                    |
  //                    F->Offset
  //
  // The fragment's offset will point to after the padding, and its computed
  // size won't include the padding.
  //
  // When the -mc-relax-all flag is used, we optimize bundling by writting the
  // padding directly into fragments when the instructions are emitted inside
  // the streamer. When the fragment is larger than the bundle size, we need to
  // ensure that it's bundle aligned. This means that if we end up with
  // multiple fragments, we must emit bundle padding between fragments.
  //
  // ".align N" is an example of a directive that introduces multiple
  // fragments. We could add a special case to handle ".align N" by emitting
  // within-fragment padding (which would produce less padding when N is less
  // than the bundle size), but for now we don't.
  //
  if (Assembler.isBundlingEnabled() && F->hasInstructions()) {
    assert(isa<MCEncodedFragment>(F) &&
           "Only MCEncodedFragment implementations have instructions");
    if (!isa<MCEncodedFragment>(F))
        return true;

    bool valid;
    uint64_t FSize = Assembler.computeFragmentSize(*this, *F, valid);
    if (!valid)
        return true;

    if (!Assembler.getRelaxAll() && FSize > Assembler.getBundleAlignSize())
      //report_fatal_error("Fragment can't be larger than a bundle size");
      return true;

    uint64_t RequiredBundlePadding = computeBundlePadding(Assembler, F,
                                                          F->Offset, FSize);
    if (RequiredBundlePadding > UINT8_MAX)
      //report_fatal_error("Padding cannot exceed 255 bytes");
      return true;

    F->setBundlePadding(static_cast<uint8_t>(RequiredBundlePadding));
    F->Offset += RequiredBundlePadding;
  }

  return false;
}

void MCAssembler::registerSymbol(const MCSymbol &Symbol, bool *Created) {
  bool New = !Symbol.isRegistered();
  if (Created)
    *Created = New;
  if (New) {
    Symbol.setIsRegistered(true);
    Symbols.push_back(&Symbol);
  }
}

void MCAssembler::writeFragmentPadding(const MCFragment &F, uint64_t FSize,
                                       MCObjectWriter *OW) const {
  // Should NOP padding be written out before this fragment?
  unsigned BundlePadding = F.getBundlePadding();
  if (BundlePadding > 0) {
    assert(isBundlingEnabled() &&
           "Writing bundle padding with disabled bundling");
    assert(F.hasInstructions() &&
           "Writing bundle padding for a fragment without instructions");

    unsigned TotalLength = BundlePadding + static_cast<unsigned>(FSize);
    if (F.alignToBundleEnd() && TotalLength > getBundleAlignSize()) {
      // If the padding itself crosses a bundle boundary, it must be emitted
      // in 2 pieces, since even nop instructions must not cross boundaries.
      //             v--------------v   <- BundleAlignSize
      //        v---------v             <- BundlePadding
      // ----------------------------
      // | Prev |####|####|    F    |
      // ----------------------------
      //        ^-------------------^   <- TotalLength
      unsigned DistanceToBoundary = TotalLength - getBundleAlignSize();
      if (!getBackend().writeNopData(DistanceToBoundary, OW))
          report_fatal_error("unable to write NOP sequence of " +
                             Twine(DistanceToBoundary) + " bytes");
      BundlePadding -= DistanceToBoundary;
    }
    if (!getBackend().writeNopData(BundlePadding, OW))
      report_fatal_error("unable to write NOP sequence of " +
                         Twine(BundlePadding) + " bytes");
  }
}

/// \brief Write the fragment \p F to the output file.
static void writeFragment(const MCAssembler &Asm, const MCAsmLayout &Layout,
                          const MCFragment &F)
{
  if (Asm.getError())
      return;

  MCObjectWriter *OW = &Asm.getWriter();

  bool valid;
  // FIXME: Embed in fragments instead?
  uint64_t FragmentSize = Asm.computeFragmentSize(Layout, F, valid);
  if (!valid) {
      Asm.setError(KS_ERR_ASM_FRAGMENT_INVALID);
      return;
  }

  Asm.writeFragmentPadding(F, FragmentSize, OW);

  // This variable (and its dummy usage) is to participate in the assert at
  // the end of the function.
  uint64_t Start = OW->getStream().tell();
  (void) Start;

  switch (F.getKind()) {
  case MCFragment::FT_Align: {
    const MCAlignFragment &AF = cast<MCAlignFragment>(F);
    assert(AF.getValueSize() && "Invalid virtual align in concrete fragment!");

    uint64_t Count = FragmentSize / AF.getValueSize();

    // FIXME: This error shouldn't actually occur (the front end should emit
    // multiple .align directives to enforce the semantics it wants), but is
    // severe enough that we want to report it. How to handle this?
    if (Count * AF.getValueSize() != FragmentSize)
      report_fatal_error("undefined .align directive, value size '" +
                        Twine(AF.getValueSize()) +
                        "' is not a divisor of padding size '" +
                        Twine(FragmentSize) + "'");

    // See if we are aligning with nops, and if so do that first to try to fill
    // the Count bytes.  Then if that did not fill any bytes or there are any
    // bytes left to fill use the Value and ValueSize to fill the rest.
    // If we are aligning with nops, ask that target to emit the right data.
    if (AF.hasEmitNops()) {
      if (!Asm.getBackend().writeNopData(Count, OW))
        report_fatal_error("unable to write nop sequence of " +
                          Twine(Count) + " bytes");
      break;
    }

    // Otherwise, write out in multiples of the value size.
    for (uint64_t i = 0; i != Count; ++i) {
      switch (AF.getValueSize()) {
      default: llvm_unreachable("Invalid size!");
      case 1: OW->write8 (uint8_t (AF.getValue())); break;
      case 2: OW->write16(uint16_t(AF.getValue())); break;
      case 4: OW->write32(uint32_t(AF.getValue())); break;
      case 8: OW->write64(uint64_t(AF.getValue())); break;
      }
    }
    break;
  }

  case MCFragment::FT_Data: 
    OW->writeBytes(cast<MCDataFragment>(F).getContents());
    break;

  case MCFragment::FT_Relaxable:
    OW->writeBytes(cast<MCRelaxableFragment>(F).getContents());
    break;

  case MCFragment::FT_CompactEncodedInst:
    OW->writeBytes(cast<MCCompactEncodedInstFragment>(F).getContents());
    break;

  case MCFragment::FT_Fill: {
    const MCFillFragment &FF = cast<MCFillFragment>(F);
    uint8_t V = FF.getValue();
    const unsigned MaxChunkSize = 16;
    char Data[MaxChunkSize];
    memcpy(Data, &V, 1);
    for (unsigned I = 1; I < MaxChunkSize; ++I)
      Data[I] = Data[0];

    uint64_t Size = FF.getSize();
    for (unsigned ChunkSize = MaxChunkSize; ChunkSize; ChunkSize /= 2) {
      StringRef Ref(Data, ChunkSize);
      for (uint64_t I = 0, E = Size / ChunkSize; I != E; ++I)
        OW->writeBytes(Ref);
      Size = Size % ChunkSize;
    }
    break;
  }

  case MCFragment::FT_LEB: {
    const MCLEBFragment &LF = cast<MCLEBFragment>(F);
    OW->writeBytes(LF.getContents());
    break;
  }

  case MCFragment::FT_SafeSEH: {
    const MCSafeSEHFragment &SF = cast<MCSafeSEHFragment>(F);
    OW->write32(SF.getSymbol()->getIndex());
    break;
  }

  case MCFragment::FT_Org: {
    const MCOrgFragment &OF = cast<MCOrgFragment>(F);

    for (uint64_t i = 0, e = FragmentSize; i != e; ++i)
      OW->write8(uint8_t(OF.getValue()));

    break;
  }

  case MCFragment::FT_Dwarf: {
    const MCDwarfLineAddrFragment &OF = cast<MCDwarfLineAddrFragment>(F);
    OW->writeBytes(OF.getContents());
    break;
  }
  case MCFragment::FT_DwarfFrame: {
    const MCDwarfCallFrameFragment &CF = cast<MCDwarfCallFrameFragment>(F);
    OW->writeBytes(CF.getContents());
    break;
  }
  case MCFragment::FT_Dummy:
    llvm_unreachable("Should not have been added");
  }

  assert(OW->getStream().tell() - Start == FragmentSize &&
         "The stream should advance by fragment size");
}

void MCAssembler::writeSectionData(const MCSection *Sec,
                                   const MCAsmLayout &Layout) const
{
  // Ignore virtual sections.
  if (Sec->isVirtualSection()) {
    assert(Layout.getSectionFileSize(Sec) == 0 && "Invalid size for section!");

    // Check that contents are only things legal inside a virtual section.
    for (const MCFragment &F : *Sec) {
      switch (F.getKind()) {
      default: llvm_unreachable("Invalid fragment in virtual section!");
      case MCFragment::FT_Data: {
        // Check that we aren't trying to write a non-zero contents (or fixups)
        // into a virtual section. This is to support clients which use standard
        // directives to fill the contents of virtual sections.
        const MCDataFragment &DF = cast<MCDataFragment>(F);
        assert(DF.fixup_begin() == DF.fixup_end() &&
               "Cannot have fixups in virtual section!");
        for (unsigned i = 0, e = DF.getContents().size(); i != e; ++i)
          if (DF.getContents()[i]) {
            if (auto *ELFSec = dyn_cast<const MCSectionELF>(Sec))
              report_fatal_error("non-zero initializer found in section '" +
                  ELFSec->getSectionName() + "'");
            else
              report_fatal_error("non-zero initializer found in virtual section");
          }
        break;
      }
      case MCFragment::FT_Align:
        // Check that we aren't trying to write a non-zero value into a virtual
        // section.
        assert((cast<MCAlignFragment>(F).getValueSize() == 0 ||
                cast<MCAlignFragment>(F).getValue() == 0) &&
               "Invalid align in virtual section!");
        break;
      case MCFragment::FT_Fill:
        assert((cast<MCFillFragment>(F).getValue() == 0) &&
               "Invalid fill in virtual section!");
        break;
      }
    }

    return;
  }

  uint64_t Start = getWriter().getStream().tell();
  (void)Start;

  setError(0);
  for (const MCFragment &F : *Sec)
    writeFragment(*this, Layout, F);

  //assert(getWriter().getStream().tell() - Start ==
  //       Layout.getSectionAddressSize(Sec));
}

std::pair<uint64_t, bool> MCAssembler::handleFixup(const MCAsmLayout &Layout,
                                                   MCFragment &F,
                                                   const MCFixup &Fixup, unsigned int &KsError) {
  // Evaluate the fixup.
  MCValue Target;
  uint64_t FixedValue;
  bool IsPCRel = Backend.getFixupKindInfo(Fixup.getKind()).Flags &
                 MCFixupKindInfo::FKF_IsPCRel;
  if (!evaluateFixup(Layout, Fixup, &F, Target, FixedValue, KsError)) {
    if (KsError) {
        // return a dummy value
        return std::make_pair(0, false);
    }
    // The fixup was unresolved, we need a relocation. Inform the object
    // writer of the relocation, and give it an opportunity to adjust the
    // fixup value if need be.
    if (const MCSymbolRefExpr *RefB = Target.getSymB()) {
        if (RefB->getKind() != MCSymbolRefExpr::VK_None) {
            KsError = KS_ERR_ASM_FIXUP_INVALID;
            // return a dummy value
            return std::make_pair(0, false);
        }
    }
    getWriter().recordRelocation(*this, Layout, &F, Fixup, Target, IsPCRel,
                                 FixedValue);
  }

  return std::make_pair(FixedValue, IsPCRel);
}

void MCAssembler::layout(MCAsmLayout &Layout, unsigned int &KsError)
{
  DEBUG_WITH_TYPE("mc-dump", {
      llvm_ks::errs() << "assembler backend - pre-layout\n--\n";
      dump(); });

  // Create dummy fragments and assign section ordinals.
  unsigned SectionIndex = 0;
  for (MCSection &Sec : *this) {
    // Create dummy fragments to eliminate any empty sections, this simplifies
    // layout.
    if (Sec.getFragmentList().empty())
      new MCDataFragment(&Sec);

    Sec.setOrdinal(SectionIndex++);
  }

  // Assign layout order indices to sections and fragments.
  for (unsigned i = 0, e = Layout.getSectionOrder().size(); i != e; ++i) {
    MCSection *Sec = Layout.getSectionOrder()[i];
    Sec->setLayoutOrder(i);

    unsigned FragmentIndex = 0;
    for (MCFragment &Frag : *Sec)
      Frag.setLayoutOrder(FragmentIndex++);
  }

  // Layout until everything fits.
  while (layoutOnce(Layout))
    continue;

  DEBUG_WITH_TYPE("mc-dump", {
      llvm_ks::errs() << "assembler backend - post-relaxation\n--\n";
      dump(); });

  // Finalize the layout, including fragment lowering.
  finishLayout(Layout);

  DEBUG_WITH_TYPE("mc-dump", {
      llvm_ks::errs() << "assembler backend - final-layout\n--\n";
      dump(); });

  // Allow the object writer a chance to perform post-layout binding (for
  // example, to set the index fields in the symbol data).
  getWriter().executePostLayoutBinding(*this, Layout);

  // Evaluate and apply the fixups, generating relocation entries as necessary.
  for (MCSection &Sec : *this) {
    for (MCFragment &Frag : Sec) {
      MCEncodedFragment *F = dyn_cast<MCEncodedFragment>(&Frag);
      // Data and relaxable fragments both have fixups.  So only process
      // those here.
      // FIXME: Is there a better way to do this?  MCEncodedFragmentWithFixups
      // being templated makes this tricky.
      if (!F || isa<MCCompactEncodedInstFragment>(F))
        continue;
      ArrayRef<MCFixup> Fixups;
      MutableArrayRef<char> Contents;
      if (auto *FragWithFixups = dyn_cast<MCDataFragment>(F)) {
        Fixups = FragWithFixups->getFixups();
        Contents = FragWithFixups->getContents();
      } else if (auto *FragWithFixups = dyn_cast<MCRelaxableFragment>(F)) {
        Fixups = FragWithFixups->getFixups();
        Contents = FragWithFixups->getContents();
      } else
        llvm_unreachable("Unknown fragment with fixups!");
      for (const MCFixup &Fixup : Fixups) {
        uint64_t FixedValue;
        bool IsPCRel;
        std::tie(FixedValue, IsPCRel) = handleFixup(Layout, *F, Fixup, KsError);
        if (KsError)
            return;
        getBackend().applyFixup(Fixup, Contents.data(),
                                Contents.size(), FixedValue, IsPCRel, KsError);
        if (KsError)
            return;
      }
    }
  }
}

void MCAssembler::Finish(unsigned int &KsError) {
  // Create the layout object.
  MCAsmLayout Layout(*this);
  layout(Layout, KsError);

  // Write the object file.
  if (!KsError) {
      getWriter().writeObject(*this, Layout);
      KsError = getError();
  }
}

bool MCAssembler::fixupNeedsRelaxation(const MCFixup &Fixup,
                                       const MCRelaxableFragment *DF,
                                       const MCAsmLayout &Layout, unsigned &KsError) const
{
  MCValue Target;
  uint64_t Value;
  bool Resolved = evaluateFixup(Layout, Fixup, DF, Target, Value, KsError);
  if (KsError) {
      KsError = KS_ERR_ASM_FIXUP_INVALID;
      // return a dummy value
      return false;
  }
  return getBackend().fixupNeedsRelaxationAdvanced(Fixup, Resolved, Value, DF,
                                                   Layout);
}

bool MCAssembler::fragmentNeedsRelaxation(const MCRelaxableFragment *F,
                                          const MCAsmLayout &Layout, unsigned &KsError) const
{
  // If this inst doesn't ever need relaxation, ignore it. This occurs when we
  // are intentionally pushing out inst fragments, or because we relaxed a
  // previous instruction to one that doesn't need relaxation.
  if (!getBackend().mayNeedRelaxation(F->getInst()))
    return false;

  for (const MCFixup &Fixup : F->getFixups())
    if (fixupNeedsRelaxation(Fixup, F, Layout, KsError))
      return true;

  return false;
}

bool MCAssembler::relaxInstruction(MCAsmLayout &Layout,
                                   MCRelaxableFragment &F)
{
  unsigned KsError = 0;
  if (!fragmentNeedsRelaxation(&F, Layout, KsError))
    return false;

  // FIXME-PERF: We could immediately lower out instructions if we can tell
  // they are fully resolved, to avoid retesting on later passes.

  // Relax the fragment.

  MCInst Relaxed;
  getBackend().relaxInstruction(F.getInst(), Relaxed);

  // Encode the new instruction.
  //
  // FIXME-PERF: If it matters, we could let the target do this. It can
  // probably do so more efficiently in many cases.
  SmallVector<MCFixup, 4> Fixups;
  SmallString<256> Code;
  raw_svector_ostream VecOS(Code);
  getEmitter().encodeInstruction(Relaxed, VecOS, Fixups, F.getSubtargetInfo(), KsError);

  // Update the fragment.
  F.setInst(Relaxed);
  F.getContents() = Code;
  F.getFixups() = Fixups;

  return true;
}

bool MCAssembler::relaxLEB(MCAsmLayout &Layout, MCLEBFragment &LF) {
  uint64_t OldSize = LF.getContents().size();
  int64_t Value;
  bool Abs = LF.getValue().evaluateKnownAbsolute(Value, Layout);
  if (!Abs)
    report_fatal_error("sleb128 and uleb128 expressions must be absolute");
  SmallString<8> &Data = LF.getContents();
  Data.clear();
  raw_svector_ostream OSE(Data);
  if (LF.isSigned())
    encodeSLEB128(Value, OSE);
  else
    encodeULEB128(Value, OSE);
  return OldSize != LF.getContents().size();
}

bool MCAssembler::relaxDwarfLineAddr(MCAsmLayout &Layout,
                                     MCDwarfLineAddrFragment &DF) {
  return false;
}

bool MCAssembler::relaxDwarfCallFrameFragment(MCAsmLayout &Layout,
                                              MCDwarfCallFrameFragment &DF) {
  return false;
}

bool MCAssembler::layoutSectionOnce(MCAsmLayout &Layout, MCSection &Sec)
{
  // Holds the first fragment which needed relaxing during this layout. It will
  // remain NULL if none were relaxed.
  // When a fragment is relaxed, all the fragments following it should get
  // invalidated because their offset is going to change.
  MCFragment *FirstRelaxedFragment = nullptr;

  // Attempt to relax all the fragments in the section.
  for (MCSection::iterator I = Sec.begin(), IE = Sec.end(); I != IE; ++I) {
    // Check if this is a fragment that needs relaxation.
    bool RelaxedFrag = false;
    switch(I->getKind()) {
    default:
      break;
    case MCFragment::FT_Relaxable:
      assert(!getRelaxAll() &&
             "Did not expect a MCRelaxableFragment in RelaxAll mode");
      RelaxedFrag = relaxInstruction(Layout, *cast<MCRelaxableFragment>(I));
      break;
    case MCFragment::FT_Dwarf:
      RelaxedFrag = relaxDwarfLineAddr(Layout,
                                       *cast<MCDwarfLineAddrFragment>(I));
      break;
    case MCFragment::FT_DwarfFrame:
      RelaxedFrag =
        relaxDwarfCallFrameFragment(Layout,
                                    *cast<MCDwarfCallFrameFragment>(I));
      break;
    case MCFragment::FT_LEB:
      RelaxedFrag = relaxLEB(Layout, *cast<MCLEBFragment>(I));
      break;
    }
    if (RelaxedFrag && !FirstRelaxedFragment)
      FirstRelaxedFragment = &*I;
  }
  if (FirstRelaxedFragment) {
    Layout.invalidateFragmentsFrom(FirstRelaxedFragment);
    return true;
  }
  return false;
}

bool MCAssembler::layoutOnce(MCAsmLayout &Layout)
{
  bool WasRelaxed = false;
  for (iterator it = begin(), ie = end(); it != ie; ++it) {
    MCSection &Sec = *it;
    while (layoutSectionOnce(Layout, Sec))
      WasRelaxed = true;
  }

  return WasRelaxed;
}

void MCAssembler::finishLayout(MCAsmLayout &Layout) {
  // The layout is done. Mark every fragment as valid.
  for (unsigned int i = 0, n = Layout.getSectionOrder().size(); i != n; ++i) {
    bool valid;
    Layout.getFragmentOffset(&*Layout.getSectionOrder()[i]->rbegin(), valid);
  }
}
