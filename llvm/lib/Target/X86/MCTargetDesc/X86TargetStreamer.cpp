#include "X86TargetStreamer.h"
#include "X86MCTargetDesc.h"
// #include "llvm/DebugInfo/CodeView/CodeView.h"
// #include "llvm/MC/MCCodeView.h"
#include "llvm/MC/MCContext.h"
// #include "llvm/MC/MCInstPrinter.h"
// #include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
// #include "llvm/MC/MCSymbol.h"
// #include "llvm/Support/FormattedStream.h"

using namespace llvm_ks;
// using namespace llvm_ks::codeview;

// MCTargetStreamer *
// llvm_ks::createX86AsmTargetStreamer(MCStreamer &S, formatted_raw_ostream &OS,
//                                     MCInstPrinter *InstPrinter) {
//   // FIXME: This makes it so we textually assemble COFF directives on ELF.
//   // That's kind of nonsensical.
//   return nullptr; // new X86WinCOFFAsmTargetStreamer(S, OS, *InstPrinter);
// }

MCTargetStreamer *
llvm_ks::createX86ObjectTargetStreamer(MCStreamer &S, const MCSubtargetInfo &STI) {
  // // No need for a special target streamer.
  // if (!STI.getTargetTriple().isOSBinFormatCOFF())
    return new X86TargetStreamer(S);
  // // Registers itself to the MCStreamer.
  // return new X86WinCOFFTargetStreamer(S);
}
