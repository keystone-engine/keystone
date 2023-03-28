//===-- Support/TargetRegistry.h - Target Registration ----------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file exposes the TargetRegistry interface, which tools can use to access
// the appropriate target specific classes (TargetMachine, AsmPrinter, etc.)
// which have been registered.
//
// Target specific class implementations should register themselves using the
// appropriate TargetRegistry interfaces.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_TARGETREGISTRY_H
#define LLVM_SUPPORT_TARGETREGISTRY_H

#include "llvm/ADT/Triple.h"
#include "llvm/Support/FormattedStream.h"
#include <cassert>
#include <memory>
#include <string>

namespace llvm_ks {
class AsmPrinter;
class MCAsmBackend;
class MCAsmInfo;
class MCAsmParser;
class MCCodeEmitter;
class MCContext;
class MCInstrAnalysis;
class MCInstrInfo;
class MCRegisterInfo;
class MCStreamer;
class MCSubtargetInfo;
class MCSymbolizer;
class MCRelocationInfo;
class MCTargetAsmParser;
class MCTargetOptions;
class MCTargetStreamer;
class TargetMachine;
class TargetOptions;
class raw_ostream;
class raw_pwrite_stream;
class formatted_raw_ostream;

MCStreamer *createNullStreamer(MCContext &Ctx);
MCStreamer *createAsmStreamer(MCContext &Ctx,
                              std::unique_ptr<formatted_raw_ostream> OS,
                              MCCodeEmitter *CE,
                              MCAsmBackend *TAB);

/// Takes ownership of \p TAB and \p CE.
MCStreamer *createELFStreamer(MCContext &Ctx, MCAsmBackend &TAB,
                              raw_pwrite_stream &OS, MCCodeEmitter *CE,
                              bool RelaxAll);
MCRelocationInfo *createMCRelocationInfo(const Triple &TT, MCContext &Ctx);

/// Target - Wrapper for Target specific information.
///
/// For registration purposes, this is a POD type so that targets can be
/// registered without the use of static constructors.
///
/// Targets should implement a single global instance of this class (which
/// will be zero initialized), and pass that instance to the TargetRegistry as
/// part of their initialization.
class Target {
public:
  friend struct TargetRegistry;

  typedef bool (*ArchMatchFnTy)(Triple::ArchType Arch);

  typedef MCAsmInfo *(*MCAsmInfoCtorFnTy)(const MCRegisterInfo &MRI,
                                          const Triple &TT);
  typedef MCInstrInfo *(*MCInstrInfoCtorFnTy)(void);
  typedef MCInstrAnalysis *(*MCInstrAnalysisCtorFnTy)(const MCInstrInfo *Info);
  typedef MCRegisterInfo *(*MCRegInfoCtorFnTy)(const Triple &TT);
  typedef MCSubtargetInfo *(*MCSubtargetInfoCtorFnTy)(const Triple &TT,
                                                      StringRef CPU,
                                                      StringRef Features);
  typedef TargetMachine *(*TargetMachineCtorTy)(
      const Target &T, const Triple &TT, StringRef CPU, StringRef Features,
      const TargetOptions &Options);
  // If it weren't for layering issues (this header is in llvm/Support, but
  // depends on MC?) this should take the Streamer by value rather than rvalue
  // reference.
  typedef AsmPrinter *(*AsmPrinterCtorTy)(
      TargetMachine &TM, std::unique_ptr<MCStreamer> &&Streamer);
  typedef MCAsmBackend *(*MCAsmBackendCtorTy)(const Target &T,
                                              const MCRegisterInfo &MRI,
                                              const Triple &TT, StringRef CPU);
  typedef MCAsmBackend *(*MCAsmBackendCtorTy2)(const Target &T,
                                              const MCRegisterInfo &MRI,
                                              const Triple &TT, StringRef CPU, const MCSubtargetInfo &STI, const MCTargetOptions &Options);
  typedef MCTargetAsmParser *(*MCAsmParserCtorTy)(
      const MCSubtargetInfo &STI, MCAsmParser &P, const MCInstrInfo &MII,
      const MCTargetOptions &Options);
  typedef MCCodeEmitter *(*MCCodeEmitterCtorTy)(const MCInstrInfo &II,
                                                const MCRegisterInfo &MRI,
                                                MCContext &Ctx);
  typedef MCStreamer *(*ELFStreamerCtorTy)(const Triple &T, MCContext &Ctx,
                                           MCAsmBackend &TAB,
                                           raw_pwrite_stream &OS,
                                           MCCodeEmitter *Emitter,
                                           bool RelaxAll);
  typedef MCStreamer *(*MachOStreamerCtorTy)(MCContext &Ctx, MCAsmBackend &TAB,
                                             raw_pwrite_stream &OS,
                                             MCCodeEmitter *Emitter,
                                             bool RelaxAll,
                                             bool DWARFMustBeAtTheEnd);
  typedef MCTargetStreamer *(*NullTargetStreamerCtorTy)(MCStreamer &S);
  typedef MCTargetStreamer *(*AsmTargetStreamerCtorTy)(
      MCStreamer &S, formatted_raw_ostream &OS);
  typedef MCTargetStreamer *(*ObjectTargetStreamerCtorTy)(
      MCStreamer &S, const MCSubtargetInfo &STI);
  typedef MCRelocationInfo *(*MCRelocationInfoCtorTy)(const Triple &TT,
                                                      MCContext &Ctx);
private:
  /// Next - The next registered target in the linked list, maintained by the
  /// TargetRegistry.
  Target *Next;

  /// The target function for checking if an architecture is supported.
  ArchMatchFnTy ArchMatchFn;

  /// Name - The target name.
  const char *Name;

  /// ShortDesc - A short description of the target.
  const char *ShortDesc;

  /// MCAsmInfoCtorFn - Constructor function for this target's MCAsmInfo, if
  /// registered.
  MCAsmInfoCtorFnTy MCAsmInfoCtorFn;

  /// MCInstrInfoCtorFn - Constructor function for this target's MCInstrInfo,
  /// if registered.
  MCInstrInfoCtorFnTy MCInstrInfoCtorFn;

  /// MCInstrAnalysisCtorFn - Constructor function for this target's
  /// MCInstrAnalysis, if registered.
  MCInstrAnalysisCtorFnTy MCInstrAnalysisCtorFn;

  /// MCRegInfoCtorFn - Constructor function for this target's MCRegisterInfo,
  /// if registered.
  MCRegInfoCtorFnTy MCRegInfoCtorFn;

  /// MCSubtargetInfoCtorFn - Constructor function for this target's
  /// MCSubtargetInfo, if registered.
  MCSubtargetInfoCtorFnTy MCSubtargetInfoCtorFn;

  /// TargetMachineCtorFn - Construction function for this target's
  /// TargetMachine, if registered.
  TargetMachineCtorTy TargetMachineCtorFn;

  /// MCAsmBackendCtorFn - Construction function for this target's
  /// MCAsmBackend, if registered.
  MCAsmBackendCtorTy MCAsmBackendCtorFn;
  MCAsmBackendCtorTy2 MCAsmBackendCtorFn2;

  /// MCAsmParserCtorFn - Construction function for this target's
  /// MCTargetAsmParser, if registered.
  MCAsmParserCtorTy MCAsmParserCtorFn;

  /// AsmPrinterCtorFn - Construction function for this target's AsmPrinter,
  /// if registered.
  AsmPrinterCtorTy AsmPrinterCtorFn;

  /// MCCodeEmitterCtorFn - Construction function for this target's
  /// CodeEmitter, if registered.
  MCCodeEmitterCtorTy MCCodeEmitterCtorFn;

  // Construction functions for the various object formats, if registered.
  ELFStreamerCtorTy ELFStreamerCtorFn;

  /// Construction function for this target's null TargetStreamer, if
  /// registered (default = nullptr).
  NullTargetStreamerCtorTy NullTargetStreamerCtorFn;

  /// Construction function for this target's asm TargetStreamer, if
  /// registered (default = nullptr).
  AsmTargetStreamerCtorTy AsmTargetStreamerCtorFn;

  /// Construction function for this target's obj TargetStreamer, if
  /// registered (default = nullptr).
  ObjectTargetStreamerCtorTy ObjectTargetStreamerCtorFn;

  /// MCRelocationInfoCtorFn - Construction function for this target's
  /// MCRelocationInfo, if registered (default = llvm_ks::createMCRelocationInfo)
  MCRelocationInfoCtorTy MCRelocationInfoCtorFn;

public:
  Target()
      : ELFStreamerCtorFn(nullptr), NullTargetStreamerCtorFn(nullptr),
        AsmTargetStreamerCtorFn(nullptr), ObjectTargetStreamerCtorFn(nullptr),
        MCRelocationInfoCtorFn(nullptr) {}

  /// @name Target Information
  /// @{

  // getNext - Return the next registered target.
  const Target *getNext() const { return Next; }

  /// getName - Get the target name.
  const char *getName() const { return Name; }

  /// getShortDescription - Get a short description of the target.
  const char *getShortDescription() const { return ShortDesc; }

  /// @}
  /// @name Feature Predicates
  /// @{

  /// hasTargetMachine - Check if this target supports code generation.
  bool hasTargetMachine() const { return TargetMachineCtorFn != nullptr; }

  /// hasMCAsmBackend - Check if this target supports .o generation.
  bool hasMCAsmBackend() const { return MCAsmBackendCtorFn != nullptr; }

  /// @}
  /// @name Feature Constructors
  /// @{

  /// createMCAsmInfo - Create a MCAsmInfo implementation for the specified
  /// target triple.
  ///
  /// \param TheTriple This argument is used to determine the target machine
  /// feature set; it should always be provided. Generally this should be
  /// either the target triple from the module, or the target triple of the
  /// host if that does not exist.
  MCAsmInfo *createMCAsmInfo(const MCRegisterInfo &MRI,
                             StringRef TheTriple) const {
    if (!MCAsmInfoCtorFn)
      return nullptr;
    return MCAsmInfoCtorFn(MRI, Triple(TheTriple));
  }

  /// createMCInstrInfo - Create a MCInstrInfo implementation.
  ///
  MCInstrInfo *createMCInstrInfo() const {
    if (!MCInstrInfoCtorFn)
      return nullptr;
    return MCInstrInfoCtorFn();
  }

  /// createMCInstrAnalysis - Create a MCInstrAnalysis implementation.
  ///
  MCInstrAnalysis *createMCInstrAnalysis(const MCInstrInfo *Info) const {
    if (!MCInstrAnalysisCtorFn)
      return nullptr;
    return MCInstrAnalysisCtorFn(Info);
  }

  /// createMCRegInfo - Create a MCRegisterInfo implementation.
  ///
  MCRegisterInfo *createMCRegInfo(StringRef TT) const {
    if (!MCRegInfoCtorFn)
      return nullptr;
    return MCRegInfoCtorFn(Triple(TT));
  }

  /// createMCSubtargetInfo - Create a MCSubtargetInfo implementation.
  ///
  /// \param TheTriple This argument is used to determine the target machine
  /// feature set; it should always be provided. Generally this should be
  /// either the target triple from the module, or the target triple of the
  /// host if that does not exist.
  /// \param CPU This specifies the name of the target CPU.
  /// \param Features This specifies the string representation of the
  /// additional target features.
  MCSubtargetInfo *createMCSubtargetInfo(StringRef TheTriple, StringRef CPU,
                                         StringRef Features) const {
    if (!MCSubtargetInfoCtorFn)
      return nullptr;
    return MCSubtargetInfoCtorFn(Triple(TheTriple), CPU, Features);
  }

  /// createTargetMachine - Create a target specific machine implementation
  /// for the specified \p Triple.
  ///
  /// \param TT This argument is used to determine the target machine
  /// feature set; it should always be provided. Generally this should be
  /// either the target triple from the module, or the target triple of the
  /// host if that does not exist.
  TargetMachine *
  createTargetMachine(StringRef TT, StringRef CPU, StringRef Features,
                      const TargetOptions &Options) const {
    if (!TargetMachineCtorFn)
      return nullptr;
    return TargetMachineCtorFn(*this, Triple(TT), CPU, Features, Options);
  }

  /// createMCAsmBackend - Create a target specific assembly parser.
  ///
  /// \param TheTriple The target triple string.
  MCAsmBackend *createMCAsmBackend(const MCRegisterInfo &MRI,
                                   StringRef TheTriple, StringRef CPU) const {
    if (!MCAsmBackendCtorFn)
      return nullptr;
    return MCAsmBackendCtorFn(*this, MRI, Triple(TheTriple), CPU);
  }

  MCAsmBackend *createMCAsmBackend2(const MCRegisterInfo &MRI,
                                   StringRef TheTriple, StringRef CPU, const MCSubtargetInfo &STI, const MCTargetOptions &Options) const {
    if (!MCAsmBackendCtorFn2)
      return nullptr;
    return MCAsmBackendCtorFn2(*this, MRI, Triple(TheTriple), CPU, STI, Options);
  }
  /// createMCAsmParser - Create a target specific assembly parser.
  ///
  /// \param Parser The target independent parser implementation to use for
  /// parsing and lexing.
  MCTargetAsmParser *createMCAsmParser(const MCSubtargetInfo &STI,
                                       MCAsmParser &Parser,
                                       const MCInstrInfo &MII,
                                       const MCTargetOptions &Options) const {
    if (!MCAsmParserCtorFn)
      return nullptr;
    return MCAsmParserCtorFn(STI, Parser, MII, Options);
  }

  /// createAsmPrinter - Create a target specific assembly printer pass.  This
  /// takes ownership of the MCStreamer object.
  AsmPrinter *createAsmPrinter(TargetMachine &TM,
                               std::unique_ptr<MCStreamer> &&Streamer) const {
    if (!AsmPrinterCtorFn)
      return nullptr;
    return AsmPrinterCtorFn(TM, std::move(Streamer));
  }

  /// createMCCodeEmitter - Create a target specific code emitter.
  MCCodeEmitter *createMCCodeEmitter(const MCInstrInfo &II,
                                     const MCRegisterInfo &MRI,
                                     MCContext &Ctx) const {
    if (!MCCodeEmitterCtorFn)
      return nullptr;
    return MCCodeEmitterCtorFn(II, MRI, Ctx);
  }

  /// Create a target specific MCStreamer.
  ///
  /// \param T The target triple.
  /// \param Ctx The target context.
  /// \param TAB The target assembler backend object. Takes ownership.
  /// \param OS The stream object.
  /// \param Emitter The target independent assembler object.Takes ownership.
  /// \param RelaxAll Relax all fixups?
  MCStreamer *createMCObjectStreamer(const Triple &T, MCContext &Ctx,
                                     MCAsmBackend &TAB, raw_pwrite_stream &OS,
                                     MCCodeEmitter *Emitter,
                                     const MCSubtargetInfo &STI, bool RelaxAll,
                                     bool DWARFMustBeAtTheEnd) const {
    MCStreamer *S;
    switch (T.getObjectFormat()) {
    default:
      llvm_unreachable("Unknown object format");
    case Triple::ELF:
      if (ELFStreamerCtorFn)
        S = ELFStreamerCtorFn(T, Ctx, TAB, OS, Emitter, RelaxAll);
      else
        S = createELFStreamer(Ctx, TAB, OS, Emitter, RelaxAll);
      break;
    }
    if (ObjectTargetStreamerCtorFn)
      ObjectTargetStreamerCtorFn(*S, STI);
    return S;
  }

  MCStreamer *createAsmStreamer(MCContext &Ctx,
                                std::unique_ptr<formatted_raw_ostream> OS,
                                MCCodeEmitter *CE,
                                MCAsmBackend *TAB) const {
    formatted_raw_ostream &OSRef = *OS;
    MCStreamer *S = llvm_ks::createAsmStreamer(Ctx, std::move(OS), CE, TAB);
    createAsmTargetStreamer(*S, OSRef);
    return S;
  }

  MCTargetStreamer *createAsmTargetStreamer(MCStreamer &S,
                                            formatted_raw_ostream &OS) const {
    if (AsmTargetStreamerCtorFn)
      return AsmTargetStreamerCtorFn(S, OS);
    return nullptr;
  }

  MCStreamer *createNullStreamer(MCContext &Ctx) const {
    MCStreamer *S = llvm_ks::createNullStreamer(Ctx);
    return S;
  }

  /// createMCRelocationInfo - Create a target specific MCRelocationInfo.
  ///
  /// \param TT The target triple.
  /// \param Ctx The target context.
  MCRelocationInfo *createMCRelocationInfo(StringRef TT, MCContext &Ctx) const {
    MCRelocationInfoCtorTy Fn = MCRelocationInfoCtorFn
                                    ? MCRelocationInfoCtorFn
                                    : llvm_ks::createMCRelocationInfo;
    return Fn(Triple(TT), Ctx);
  }

  /// @}
};

/// TargetRegistry - Generic interface to target specific features.
struct TargetRegistry {
  // FIXME: Make this a namespace, probably just move all the Register*
  // functions into Target (currently they all just set members on the Target
  // anyway, and Target friends this class so those functions can...
  // function).
  TargetRegistry() = delete;

  class iterator
      : public std::iterator<std::forward_iterator_tag, Target, ptrdiff_t> {
    const Target *Current;
    explicit iterator(Target *T) : Current(T) {}
    friend struct TargetRegistry;

  public:
    iterator() : Current(nullptr) {}

    bool operator==(const iterator &x) const { return Current == x.Current; }
    bool operator!=(const iterator &x) const { return !operator==(x); }

    // Iterator traversal: forward iteration only
    iterator &operator++() { // Preincrement
      assert(Current && "Cannot increment end iterator!");
      Current = Current->getNext();
      return *this;
    }
    iterator operator++(int) { // Postincrement
      iterator tmp = *this;
      ++*this;
      return tmp;
    }

    const Target &operator*() const {
      assert(Current && "Cannot dereference end iterator!");
      return *Current;
    }

    const Target *operator->() const { return &operator*(); }
  };

  /// printRegisteredTargetsForVersion - Print the registered targets
  /// appropriately for inclusion in a tool's version output.
  static void printRegisteredTargetsForVersion();

  /// @name Registry Access
  /// @{

  static iterator_range<iterator> targets();

  /// lookupTarget - Lookup a target based on a target triple.
  ///
  /// \param Triple - The triple to use for finding a target.
  /// \param Error - On failure, an error string describing why no target was
  /// found.
  static const Target *lookupTarget(const std::string &Triple,
                                    std::string &Error);

  /// lookupTarget - Lookup a target based on an architecture name
  /// and a target triple.  If the architecture name is non-empty,
  /// then the lookup is done by architecture.  Otherwise, the target
  /// triple is used.
  ///
  /// \param ArchName - The architecture to use for finding a target.
  /// \param TheTriple - The triple to use for finding a target.  The
  /// triple is updated with canonical architecture name if a lookup
  /// by architecture is done.
  /// \param Error - On failure, an error string describing why no target was
  /// found.
  static const Target *lookupTarget(const std::string &ArchName,
                                    Triple &TheTriple, std::string &Error);

  /// @}
  /// @name Target Registration
  /// @{

  /// RegisterTarget - Register the given target. Attempts to register a
  /// target which has already been registered will be ignored.
  ///
  /// Clients are responsible for ensuring that registration doesn't occur
  /// while another thread is attempting to access the registry. Typically
  /// this is done by initializing all targets at program startup.
  ///
  /// @param T - The target being registered.
  /// @param Name - The target name. This should be a static string.
  /// @param ShortDesc - A short target description. This should be a static
  /// string.
  /// @param ArchMatchFn - The arch match checking function for this target.
  static void RegisterTarget(Target &T, const char *Name, const char *ShortDesc,
                             Target::ArchMatchFnTy ArchMatchFn);

  /// RegisterMCAsmInfo - Register a MCAsmInfo implementation for the
  /// given target.
  ///
  /// Clients are responsible for ensuring that registration doesn't occur
  /// while another thread is attempting to access the registry. Typically
  /// this is done by initializing all targets at program startup.
  ///
  /// @param T - The target being registered.
  /// @param Fn - A function to construct a MCAsmInfo for the target.
  static void RegisterMCAsmInfo(Target &T, Target::MCAsmInfoCtorFnTy Fn) {
    T.MCAsmInfoCtorFn = Fn;
  }

  /// RegisterMCInstrInfo - Register a MCInstrInfo implementation for the
  /// given target.
  ///
  /// Clients are responsible for ensuring that registration doesn't occur
  /// while another thread is attempting to access the registry. Typically
  /// this is done by initializing all targets at program startup.
  ///
  /// @param T - The target being registered.
  /// @param Fn - A function to construct a MCInstrInfo for the target.
  static void RegisterMCInstrInfo(Target &T, Target::MCInstrInfoCtorFnTy Fn) {
    T.MCInstrInfoCtorFn = Fn;
  }

  /// RegisterMCInstrAnalysis - Register a MCInstrAnalysis implementation for
  /// the given target.
  static void RegisterMCInstrAnalysis(Target &T,
                                      Target::MCInstrAnalysisCtorFnTy Fn) {
    T.MCInstrAnalysisCtorFn = Fn;
  }

  /// RegisterMCRegInfo - Register a MCRegisterInfo implementation for the
  /// given target.
  ///
  /// Clients are responsible for ensuring that registration doesn't occur
  /// while another thread is attempting to access the registry. Typically
  /// this is done by initializing all targets at program startup.
  ///
  /// @param T - The target being registered.
  /// @param Fn - A function to construct a MCRegisterInfo for the target.
  static void RegisterMCRegInfo(Target &T, Target::MCRegInfoCtorFnTy Fn) {
    T.MCRegInfoCtorFn = Fn;
  }

  /// RegisterMCSubtargetInfo - Register a MCSubtargetInfo implementation for
  /// the given target.
  ///
  /// Clients are responsible for ensuring that registration doesn't occur
  /// while another thread is attempting to access the registry. Typically
  /// this is done by initializing all targets at program startup.
  ///
  /// @param T - The target being registered.
  /// @param Fn - A function to construct a MCSubtargetInfo for the target.
  static void RegisterMCSubtargetInfo(Target &T,
                                      Target::MCSubtargetInfoCtorFnTy Fn) {
    T.MCSubtargetInfoCtorFn = Fn;
  }

  /// RegisterTargetMachine - Register a TargetMachine implementation for the
  /// given target.
  ///
  /// Clients are responsible for ensuring that registration doesn't occur
  /// while another thread is attempting to access the registry. Typically
  /// this is done by initializing all targets at program startup.
  ///
  /// @param T - The target being registered.
  /// @param Fn - A function to construct a TargetMachine for the target.
  static void RegisterTargetMachine(Target &T, Target::TargetMachineCtorTy Fn) {
    T.TargetMachineCtorFn = Fn;
  }

  /// RegisterMCAsmBackend - Register a MCAsmBackend implementation for the
  /// given target.
  ///
  /// Clients are responsible for ensuring that registration doesn't occur
  /// while another thread is attempting to access the registry. Typically
  /// this is done by initializing all targets at program startup.
  ///
  /// @param T - The target being registered.
  /// @param Fn - A function to construct an AsmBackend for the target.
  static void RegisterMCAsmBackend(Target &T, Target::MCAsmBackendCtorTy Fn) {
    T.MCAsmBackendCtorFn = Fn;
  }
  static void RegisterMCAsmBackend2(Target &T, Target::MCAsmBackendCtorTy2 Fn) {
    T.MCAsmBackendCtorFn2 = Fn;
  }

  /// RegisterMCAsmParser - Register a MCTargetAsmParser implementation for
  /// the given target.
  ///
  /// Clients are responsible for ensuring that registration doesn't occur
  /// while another thread is attempting to access the registry. Typically
  /// this is done by initializing all targets at program startup.
  ///
  /// @param T - The target being registered.
  /// @param Fn - A function to construct an MCTargetAsmParser for the target.
  static void RegisterMCAsmParser(Target &T, Target::MCAsmParserCtorTy Fn) {
    T.MCAsmParserCtorFn = Fn;
  }

  /// RegisterAsmPrinter - Register an AsmPrinter implementation for the given
  /// target.
  ///
  /// Clients are responsible for ensuring that registration doesn't occur
  /// while another thread is attempting to access the registry. Typically
  /// this is done by initializing all targets at program startup.
  ///
  /// @param T - The target being registered.
  /// @param Fn - A function to construct an AsmPrinter for the target.
  static void RegisterAsmPrinter(Target &T, Target::AsmPrinterCtorTy Fn) {
    T.AsmPrinterCtorFn = Fn;
  }

  /// RegisterMCCodeEmitter - Register a MCCodeEmitter implementation for the
  /// given target.
  ///
  /// Clients are responsible for ensuring that registration doesn't occur
  /// while another thread is attempting to access the registry. Typically
  /// this is done by initializing all targets at program startup.
  ///
  /// @param T - The target being registered.
  /// @param Fn - A function to construct an MCCodeEmitter for the target.
  static void RegisterMCCodeEmitter(Target &T, Target::MCCodeEmitterCtorTy Fn) {
    T.MCCodeEmitterCtorFn = Fn;
  }

  static void RegisterELFStreamer(Target &T, Target::ELFStreamerCtorTy Fn) {
    T.ELFStreamerCtorFn = Fn;
  }

  static void RegisterNullTargetStreamer(Target &T,
                                         Target::NullTargetStreamerCtorTy Fn) {
    T.NullTargetStreamerCtorFn = Fn;
  }

  static void RegisterAsmTargetStreamer(Target &T,
                                        Target::AsmTargetStreamerCtorTy Fn) {
    T.AsmTargetStreamerCtorFn = Fn;
  }

  static void
  RegisterObjectTargetStreamer(Target &T,
                               Target::ObjectTargetStreamerCtorTy Fn) {
    T.ObjectTargetStreamerCtorFn = Fn;
  }

  /// RegisterMCRelocationInfo - Register an MCRelocationInfo
  /// implementation for the given target.
  ///
  /// Clients are responsible for ensuring that registration doesn't occur
  /// while another thread is attempting to access the registry. Typically
  /// this is done by initializing all targets at program startup.
  ///
  /// @param T - The target being registered.
  /// @param Fn - A function to construct an MCRelocationInfo for the target.
  static void RegisterMCRelocationInfo(Target &T,
                                       Target::MCRelocationInfoCtorTy Fn) {
    T.MCRelocationInfoCtorFn = Fn;
  }

  /// @}
};

//===--------------------------------------------------------------------===//

/// RegisterTarget - Helper template for registering a target, for use in the
/// target's initialization function. Usage:
///
///
/// Target TheFooTarget; // The global target instance.
///
/// extern "C" void LLVMInitializeFooTargetInfo() {
///   RegisterTarget<Triple::foo> X(TheFooTarget, "foo", "Foo description");
/// }
template <Triple::ArchType TargetArchType = Triple::UnknownArch>
struct RegisterTarget {
  RegisterTarget(Target &T, const char *Name, const char *Desc) {
    TargetRegistry::RegisterTarget(T, Name, Desc, &getArchMatch);
  }

  static bool getArchMatch(Triple::ArchType Arch) {
    return Arch == TargetArchType;
  }
};

/// RegisterMCAsmInfo - Helper template for registering a target assembly info
/// implementation.  This invokes the static "Create" method on the class to
/// actually do the construction.  Usage:
///
/// extern "C" void LLVMInitializeFooTarget() {
///   extern Target TheFooTarget;
///   RegisterMCAsmInfo<FooMCAsmInfo> X(TheFooTarget);
/// }
template <class MCAsmInfoImpl> struct RegisterMCAsmInfo {
  RegisterMCAsmInfo(Target &T) {
    TargetRegistry::RegisterMCAsmInfo(T, &Allocator);
  }

private:
  static MCAsmInfo *Allocator(const MCRegisterInfo & /*MRI*/,
                              const Triple &TT) {
    return new MCAsmInfoImpl(TT);
  }
};

/// RegisterMCAsmInfoFn - Helper template for registering a target assembly info
/// implementation.  This invokes the specified function to do the
/// construction.  Usage:
///
/// extern "C" void LLVMInitializeFooTarget() {
///   extern Target TheFooTarget;
///   RegisterMCAsmInfoFn X(TheFooTarget, TheFunction);
/// }
struct RegisterMCAsmInfoFn {
  RegisterMCAsmInfoFn(Target &T, Target::MCAsmInfoCtorFnTy Fn) {
    TargetRegistry::RegisterMCAsmInfo(T, Fn);
  }
};

/// RegisterMCInstrInfo - Helper template for registering a target instruction
/// info implementation.  This invokes the static "Create" method on the class
/// to actually do the construction.  Usage:
///
/// extern "C" void LLVMInitializeFooTarget() {
///   extern Target TheFooTarget;
///   RegisterMCInstrInfo<FooMCInstrInfo> X(TheFooTarget);
/// }
template <class MCInstrInfoImpl> struct RegisterMCInstrInfo {
  RegisterMCInstrInfo(Target &T) {
    TargetRegistry::RegisterMCInstrInfo(T, &Allocator);
  }

private:
  static MCInstrInfo *Allocator() { return new MCInstrInfoImpl(); }
};

/// RegisterMCInstrInfoFn - Helper template for registering a target
/// instruction info implementation.  This invokes the specified function to
/// do the construction.  Usage:
///
/// extern "C" void LLVMInitializeFooTarget() {
///   extern Target TheFooTarget;
///   RegisterMCInstrInfoFn X(TheFooTarget, TheFunction);
/// }
struct RegisterMCInstrInfoFn {
  RegisterMCInstrInfoFn(Target &T, Target::MCInstrInfoCtorFnTy Fn) {
    TargetRegistry::RegisterMCInstrInfo(T, Fn);
  }
};

/// RegisterMCInstrAnalysis - Helper template for registering a target
/// instruction analyzer implementation.  This invokes the static "Create"
/// method on the class to actually do the construction.  Usage:
///
/// extern "C" void LLVMInitializeFooTarget() {
///   extern Target TheFooTarget;
///   RegisterMCInstrAnalysis<FooMCInstrAnalysis> X(TheFooTarget);
/// }
template <class MCInstrAnalysisImpl> struct RegisterMCInstrAnalysis {
  RegisterMCInstrAnalysis(Target &T) {
    TargetRegistry::RegisterMCInstrAnalysis(T, &Allocator);
  }

private:
  static MCInstrAnalysis *Allocator(const MCInstrInfo *Info) {
    return new MCInstrAnalysisImpl(Info);
  }
};

/// RegisterMCInstrAnalysisFn - Helper template for registering a target
/// instruction analyzer implementation.  This invokes the specified function
/// to do the construction.  Usage:
///
/// extern "C" void LLVMInitializeFooTarget() {
///   extern Target TheFooTarget;
///   RegisterMCInstrAnalysisFn X(TheFooTarget, TheFunction);
/// }
struct RegisterMCInstrAnalysisFn {
  RegisterMCInstrAnalysisFn(Target &T, Target::MCInstrAnalysisCtorFnTy Fn) {
    TargetRegistry::RegisterMCInstrAnalysis(T, Fn);
  }
};

/// RegisterMCRegInfo - Helper template for registering a target register info
/// implementation.  This invokes the static "Create" method on the class to
/// actually do the construction.  Usage:
///
/// extern "C" void LLVMInitializeFooTarget() {
///   extern Target TheFooTarget;
///   RegisterMCRegInfo<FooMCRegInfo> X(TheFooTarget);
/// }
template <class MCRegisterInfoImpl> struct RegisterMCRegInfo {
  RegisterMCRegInfo(Target &T) {
    TargetRegistry::RegisterMCRegInfo(T, &Allocator);
  }

private:
  static MCRegisterInfo *Allocator(const Triple & /*TT*/) {
    return new MCRegisterInfoImpl();
  }
};

/// RegisterMCRegInfoFn - Helper template for registering a target register
/// info implementation.  This invokes the specified function to do the
/// construction.  Usage:
///
/// extern "C" void LLVMInitializeFooTarget() {
///   extern Target TheFooTarget;
///   RegisterMCRegInfoFn X(TheFooTarget, TheFunction);
/// }
struct RegisterMCRegInfoFn {
  RegisterMCRegInfoFn(Target &T, Target::MCRegInfoCtorFnTy Fn) {
    TargetRegistry::RegisterMCRegInfo(T, Fn);
  }
};

/// RegisterMCSubtargetInfo - Helper template for registering a target
/// subtarget info implementation.  This invokes the static "Create" method
/// on the class to actually do the construction.  Usage:
///
/// extern "C" void LLVMInitializeFooTarget() {
///   extern Target TheFooTarget;
///   RegisterMCSubtargetInfo<FooMCSubtargetInfo> X(TheFooTarget);
/// }
template <class MCSubtargetInfoImpl> struct RegisterMCSubtargetInfo {
  RegisterMCSubtargetInfo(Target &T) {
    TargetRegistry::RegisterMCSubtargetInfo(T, &Allocator);
  }

private:
  static MCSubtargetInfo *Allocator(const Triple & /*TT*/, StringRef /*CPU*/,
                                    StringRef /*FS*/) {
    return new MCSubtargetInfoImpl();
  }
};

/// RegisterMCSubtargetInfoFn - Helper template for registering a target
/// subtarget info implementation.  This invokes the specified function to
/// do the construction.  Usage:
///
/// extern "C" void LLVMInitializeFooTarget() {
///   extern Target TheFooTarget;
///   RegisterMCSubtargetInfoFn X(TheFooTarget, TheFunction);
/// }
struct RegisterMCSubtargetInfoFn {
  RegisterMCSubtargetInfoFn(Target &T, Target::MCSubtargetInfoCtorFnTy Fn) {
    TargetRegistry::RegisterMCSubtargetInfo(T, Fn);
  }
};

/// RegisterTargetMachine - Helper template for registering a target machine
/// implementation, for use in the target machine initialization
/// function. Usage:
///
/// extern "C" void LLVMInitializeFooTarget() {
///   extern Target TheFooTarget;
///   RegisterTargetMachine<FooTargetMachine> X(TheFooTarget);
/// }
template <class TargetMachineImpl> struct RegisterTargetMachine {
  RegisterTargetMachine(Target &T) {
    TargetRegistry::RegisterTargetMachine(T, &Allocator);
  }

private:
  static TargetMachine *Allocator(const Target &T, const Triple &TT,
                                  StringRef CPU, StringRef FS,
                                  const TargetOptions &Options) {
    return new TargetMachineImpl(T, TT, CPU, FS, Options);
  }
};

/// RegisterMCAsmBackend - Helper template for registering a target specific
/// assembler backend. Usage:
///
/// extern "C" void LLVMInitializeFooMCAsmBackend() {
///   extern Target TheFooTarget;
///   RegisterMCAsmBackend<FooAsmLexer> X(TheFooTarget);
/// }
template <class MCAsmBackendImpl> struct RegisterMCAsmBackend {
  RegisterMCAsmBackend(Target &T) {
    TargetRegistry::RegisterMCAsmBackend(T, &Allocator);
  }

private:
  static MCAsmBackend *Allocator(const Target &T, const MCRegisterInfo &MRI,
                                 const Triple &TheTriple, StringRef CPU) {
    return new MCAsmBackendImpl(T, MRI, TheTriple, CPU);
  }
};

/// RegisterMCAsmParser - Helper template for registering a target specific
/// assembly parser, for use in the target machine initialization
/// function. Usage:
///
/// extern "C" void LLVMInitializeFooMCAsmParser() {
///   extern Target TheFooTarget;
///   RegisterMCAsmParser<FooAsmParser> X(TheFooTarget);
/// }
template <class MCAsmParserImpl> struct RegisterMCAsmParser {
  RegisterMCAsmParser(Target &T) {
    TargetRegistry::RegisterMCAsmParser(T, &Allocator);
  }

private:
  static MCTargetAsmParser *Allocator(const MCSubtargetInfo &STI,
                                      MCAsmParser &P, const MCInstrInfo &MII,
                                      const MCTargetOptions &Options) {
    return new MCAsmParserImpl(STI, P, MII, Options);
  }
};

/// RegisterAsmPrinter - Helper template for registering a target specific
/// assembly printer, for use in the target machine initialization
/// function. Usage:
///
/// extern "C" void LLVMInitializeFooAsmPrinter() {
///   extern Target TheFooTarget;
///   RegisterAsmPrinter<FooAsmPrinter> X(TheFooTarget);
/// }
template <class AsmPrinterImpl> struct RegisterAsmPrinter {
  RegisterAsmPrinter(Target &T) {
    TargetRegistry::RegisterAsmPrinter(T, &Allocator);
  }

private:
  static AsmPrinter *Allocator(TargetMachine &TM,
                               std::unique_ptr<MCStreamer> &&Streamer) {
    return new AsmPrinterImpl(TM, std::move(Streamer));
  }
};

/// RegisterMCCodeEmitter - Helper template for registering a target specific
/// machine code emitter, for use in the target initialization
/// function. Usage:
///
/// extern "C" void LLVMInitializeFooMCCodeEmitter() {
///   extern Target TheFooTarget;
///   RegisterMCCodeEmitter<FooCodeEmitter> X(TheFooTarget);
/// }
template <class MCCodeEmitterImpl> struct RegisterMCCodeEmitter {
  RegisterMCCodeEmitter(Target &T) {
    TargetRegistry::RegisterMCCodeEmitter(T, &Allocator);
  }

private:
  static MCCodeEmitter *Allocator(const MCInstrInfo & /*II*/,
                                  const MCRegisterInfo & /*MRI*/,
                                  MCContext & /*Ctx*/) {
    return new MCCodeEmitterImpl();
  }
};
}

#endif
