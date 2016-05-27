//===-- MCObjectFileInfo.cpp - Object File Information --------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/Triple.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCSection.h"
#include "llvm/MC/MCSectionELF.h"

using namespace llvm;

void MCObjectFileInfo::initELFMCObjectFileInfo(Triple T) {
  switch (T.getArch()) {
  case Triple::mips:
  case Triple::mipsel:
    FDECFIEncoding = dwarf::DW_EH_PE_sdata4;
    break;
  case Triple::mips64:
  case Triple::mips64el:
    FDECFIEncoding = dwarf::DW_EH_PE_sdata8;
    break;
  case Triple::x86_64:
    break;
  default:
    FDECFIEncoding = dwarf::DW_EH_PE_pcrel | dwarf::DW_EH_PE_sdata4;
    break;
  }

  switch (T.getArch()) {
  case Triple::arm:
  case Triple::armeb:
  case Triple::thumb:
  case Triple::thumbeb:
    if (Ctx->getAsmInfo()->getExceptionHandlingType() == ExceptionHandling::ARM)
      break;
    // Fallthrough if not using EHABI
  case Triple::ppc:
  case Triple::x86:
    break;
  case Triple::x86_64:
    break;
  case Triple::aarch64:
  case Triple::aarch64_be:
    // The small model guarantees static code/data size < 4GB, but not where it
    // will be in memory. Most of these could end up >2GB away so even a signed
    // pc-relative 32-bit address is insufficient, theoretically.
    break;
  case Triple::mips:
  case Triple::mipsel:
  case Triple::mips64:
  case Triple::mips64el:
    // MIPS uses indirect pointer to refer personality functions and types, so
    // that the eh_frame section can be read-only. DW.ref.personality will be
    // generated for relocation.
    PersonalityEncoding = dwarf::DW_EH_PE_indirect;
    // FIXME: The N64 ABI probably ought to use DW_EH_PE_sdata8 but we can't
    //        identify N64 from just a triple.
    TTypeEncoding = dwarf::DW_EH_PE_indirect | dwarf::DW_EH_PE_pcrel |
                    dwarf::DW_EH_PE_sdata4;
    // We don't support PC-relative LSDA references in GAS so we use the default
    // DW_EH_PE_absptr for those.
    break;
  case Triple::ppc64:
  case Triple::ppc64le:
    PersonalityEncoding = dwarf::DW_EH_PE_indirect | dwarf::DW_EH_PE_pcrel |
      dwarf::DW_EH_PE_udata8;
    LSDAEncoding = dwarf::DW_EH_PE_pcrel | dwarf::DW_EH_PE_udata8;
    TTypeEncoding = dwarf::DW_EH_PE_indirect | dwarf::DW_EH_PE_pcrel |
      dwarf::DW_EH_PE_udata8;
    break;
  case Triple::sparcel:
  case Triple::sparc:
    break;
  case Triple::sparcv9:
    LSDAEncoding = dwarf::DW_EH_PE_pcrel | dwarf::DW_EH_PE_sdata4;
    break;
  case Triple::systemz:
    // All currently-defined code models guarantee that 4-byte PC-relative
    // values will be in range.
    break;
  default:
    break;
  }

  unsigned EHSectionType = T.getArch() == Triple::x86_64
                               ? ELF::SHT_X86_64_UNWIND
                               : ELF::SHT_PROGBITS;

  // Solaris requires different flags for .eh_frame to seemingly every other
  // platform.
  unsigned EHSectionFlags = ELF::SHF_ALLOC;
  if (T.isOSSolaris() && T.getArch() != Triple::x86_64)
    EHSectionFlags |= ELF::SHF_WRITE;

  // ELF
  BSSSection = Ctx->getELFSection(".bss", ELF::SHT_NOBITS,
                                  ELF::SHF_WRITE | ELF::SHF_ALLOC);

  TextSection = Ctx->getELFSection(".text", ELF::SHT_PROGBITS,
                                   ELF::SHF_EXECINSTR | ELF::SHF_ALLOC);

  DataSection = Ctx->getELFSection(".data", ELF::SHT_PROGBITS,
                                   ELF::SHF_WRITE | ELF::SHF_ALLOC);

  ReadOnlySection =
      Ctx->getELFSection(".rodata", ELF::SHT_PROGBITS, ELF::SHF_ALLOC);

  TLSDataSection =
      Ctx->getELFSection(".tdata", ELF::SHT_PROGBITS,
                         ELF::SHF_ALLOC | ELF::SHF_TLS | ELF::SHF_WRITE);

  TLSBSSSection = Ctx->getELFSection(
      ".tbss", ELF::SHT_NOBITS, ELF::SHF_ALLOC | ELF::SHF_TLS | ELF::SHF_WRITE);

  DataRelROSection = Ctx->getELFSection(".data.rel.ro", ELF::SHT_PROGBITS,
                                        ELF::SHF_ALLOC | ELF::SHF_WRITE);

  MergeableConst4Section =
      Ctx->getELFSection(".rodata.cst4", ELF::SHT_PROGBITS,
                         ELF::SHF_ALLOC | ELF::SHF_MERGE, 4, "");

  MergeableConst8Section =
      Ctx->getELFSection(".rodata.cst8", ELF::SHT_PROGBITS,
                         ELF::SHF_ALLOC | ELF::SHF_MERGE, 8, "");

  MergeableConst16Section =
      Ctx->getELFSection(".rodata.cst16", ELF::SHT_PROGBITS,
                         ELF::SHF_ALLOC | ELF::SHF_MERGE, 16, "");

  StaticCtorSection = Ctx->getELFSection(".ctors", ELF::SHT_PROGBITS,
                                         ELF::SHF_ALLOC | ELF::SHF_WRITE);

  StaticDtorSection = Ctx->getELFSection(".dtors", ELF::SHT_PROGBITS,
                                         ELF::SHF_ALLOC | ELF::SHF_WRITE);

  // Exception Handling Sections.

  // FIXME: We're emitting LSDA info into a readonly section on ELF, even though
  // it contains relocatable pointers.  In PIC mode, this is probably a big
  // runtime hit for C++ apps.  Either the contents of the LSDA need to be
  // adjusted or this should be a data section.
  LSDASection = Ctx->getELFSection(".gcc_except_table", ELF::SHT_PROGBITS,
                                   ELF::SHF_ALLOC);

  // Debug Info Sections.
  DwarfAbbrevSection = Ctx->getELFSection(".debug_abbrev", ELF::SHT_PROGBITS, 0,
                                          "section_abbrev");
  DwarfInfoSection =
      Ctx->getELFSection(".debug_info", ELF::SHT_PROGBITS, 0, "section_info");
  DwarfLineSection = Ctx->getELFSection(".debug_line", ELF::SHT_PROGBITS, 0);
  DwarfFrameSection = Ctx->getELFSection(".debug_frame", ELF::SHT_PROGBITS, 0);
  DwarfPubNamesSection =
      Ctx->getELFSection(".debug_pubnames", ELF::SHT_PROGBITS, 0);
  DwarfPubTypesSection =
      Ctx->getELFSection(".debug_pubtypes", ELF::SHT_PROGBITS, 0);
  DwarfGnuPubNamesSection =
      Ctx->getELFSection(".debug_gnu_pubnames", ELF::SHT_PROGBITS, 0);
  DwarfGnuPubTypesSection =
      Ctx->getELFSection(".debug_gnu_pubtypes", ELF::SHT_PROGBITS, 0);
  DwarfStrSection =
      Ctx->getELFSection(".debug_str", ELF::SHT_PROGBITS,
                         ELF::SHF_MERGE | ELF::SHF_STRINGS, 1, "");
  DwarfLocSection = Ctx->getELFSection(".debug_loc", ELF::SHT_PROGBITS, 0);
  DwarfARangesSection =
      Ctx->getELFSection(".debug_aranges", ELF::SHT_PROGBITS, 0);
  DwarfRangesSection =
      Ctx->getELFSection(".debug_ranges", ELF::SHT_PROGBITS, 0, "debug_range");
  DwarfMacinfoSection = Ctx->getELFSection(".debug_macinfo", ELF::SHT_PROGBITS,
                                           0, "debug_macinfo");

  // DWARF5 Experimental Debug Info

  // Accelerator Tables
  DwarfAccelNamesSection =
      Ctx->getELFSection(".apple_names", ELF::SHT_PROGBITS, 0, "names_begin");
  DwarfAccelObjCSection =
      Ctx->getELFSection(".apple_objc", ELF::SHT_PROGBITS, 0, "objc_begin");
  DwarfAccelNamespaceSection = Ctx->getELFSection(
      ".apple_namespaces", ELF::SHT_PROGBITS, 0, "namespac_begin");
  DwarfAccelTypesSection =
      Ctx->getELFSection(".apple_types", ELF::SHT_PROGBITS, 0, "types_begin");

  // Fission Sections
  DwarfInfoDWOSection =
      Ctx->getELFSection(".debug_info.dwo", ELF::SHT_PROGBITS, 0);
  DwarfTypesDWOSection =
      Ctx->getELFSection(".debug_types.dwo", ELF::SHT_PROGBITS, 0);
  DwarfAbbrevDWOSection =
      Ctx->getELFSection(".debug_abbrev.dwo", ELF::SHT_PROGBITS, 0);
  DwarfStrDWOSection =
      Ctx->getELFSection(".debug_str.dwo", ELF::SHT_PROGBITS,
                         ELF::SHF_MERGE | ELF::SHF_STRINGS, 1, "");
  DwarfLineDWOSection =
      Ctx->getELFSection(".debug_line.dwo", ELF::SHT_PROGBITS, 0);
  DwarfLocDWOSection =
      Ctx->getELFSection(".debug_loc.dwo", ELF::SHT_PROGBITS, 0, "skel_loc");
  DwarfStrOffDWOSection =
      Ctx->getELFSection(".debug_str_offsets.dwo", ELF::SHT_PROGBITS, 0);
  DwarfAddrSection =
      Ctx->getELFSection(".debug_addr", ELF::SHT_PROGBITS, 0, "addr_sec");

  // DWP Sections
  DwarfCUIndexSection =
      Ctx->getELFSection(".debug_cu_index", ELF::SHT_PROGBITS, 0);
  DwarfTUIndexSection =
      Ctx->getELFSection(".debug_tu_index", ELF::SHT_PROGBITS, 0);

  StackMapSection =
      Ctx->getELFSection(".llvm_stackmaps", ELF::SHT_PROGBITS, ELF::SHF_ALLOC);

  FaultMapSection =
      Ctx->getELFSection(".llvm_faultmaps", ELF::SHT_PROGBITS, ELF::SHF_ALLOC);

  EHFrameSection =
      Ctx->getELFSection(".eh_frame", EHSectionType, EHSectionFlags);
}

void MCObjectFileInfo::InitMCObjectFileInfo(const Triple &TheTriple,
                                            MCContext &ctx) {
  Ctx = &ctx;

  // Common.
  CommDirectiveSupportsAlignment = true;
  SupportsWeakOmittedEHFrame = true;
  SupportsCompactUnwindWithoutEHFrame = false;
  OmitDwarfIfHaveCompactUnwind = false;

  PersonalityEncoding = LSDAEncoding = FDECFIEncoding = TTypeEncoding =
      dwarf::DW_EH_PE_absptr;

  CompactUnwindDwarfEHFrameOnly = 0;

  EHFrameSection = nullptr;             // Created on demand.
  CompactUnwindSection = nullptr;       // Used only by selected targets.
  DwarfAccelNamesSection = nullptr;     // Used only by selected targets.
  DwarfAccelObjCSection = nullptr;      // Used only by selected targets.
  DwarfAccelNamespaceSection = nullptr; // Used only by selected targets.
  DwarfAccelTypesSection = nullptr;     // Used only by selected targets.

  TT = TheTriple;

  Env = IsELF;
  initELFMCObjectFileInfo(TT);
}

MCSection *MCObjectFileInfo::getDwarfTypesSection(uint64_t Hash) const {
  return Ctx->getELFSection(".debug_types", ELF::SHT_PROGBITS, ELF::SHF_GROUP,
                            0, utostr(Hash));
}
