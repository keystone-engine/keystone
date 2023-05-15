# Keystone RISC-V port documentation
The intended way to read this documentation is to open [https://github.com/keystone-engine/keystone/pull/549/files](https://github.com/keystone-engine/keystone/pull/549/files) and scroll the files in the file tree as they are mentioned. This will allow you to understand the references made in this document and see the actual changes to the code. For instructions on how to build keystone, check keystone/docs/COMPILE.md.

## Explanation of the already existing Keystone repository and tools
This chapter will explain the important parts of the existing Keystone repository needed to understand Keystone, before delving deeper into what files need to be changed in order to introduce a new archtecture.

### bindings
This folder includes the bindings for each of the supported languages. See the Build bindings chapter below to see how to generate the bindings for a new architecture.

### include/keystone
Defines constants both per architecture and Keystone wide.

### kstool
A tool to test or use Keystone in command line. Takes two arguments, the target and an assembly string, then returns the assembled machine (byte) code. To do that, it first initializes a Keystone object, which initializes all target information, MC objects, AsmParsers, instruction information, subtarget information, MCAsmBackend and flags. If this is successful, the assembly string will be parsed in the ks_asm by the target specific AsmParser. If this does not throw an error, the output machine code is printed.

### llvm/keystone 
Contains all support functions that Keystone (and kstool) requires for initializing and assembling, definition of the Keystone struct and constants. This is the main contribution of the Keystone project as it defines the program execution flow, calls to llvm and the error handling (and reporting). 

### llvm/include/llvm, llvm/lib/MC and llvm/lib/Support
These folders contain most of the initial forked llvm, including ADT (advanced data types used by llvm), AsmParser (the main assembly parser interface), Config, MC (contains all required Machine Code (MC) objects, Keystone uses this part of llvm the most), Object and Support (includes relocation info per architecture, definition of file type constants, helper functions, etc.) folders. The first folder contains mainly header (.h) files, while the latter two contain c++ (.cpp) files for the same use. Many of these files have been altered and extended for use in Keystone.

### Other directories
In suite, there are regression tests, afl implementation for Keystone and fuzzing tests. In docs, there is documentation on how to compile/build the project and some articles. In the main directory one can find release notes, multiple make scripts for different purposes, .NOTE which contains a checklist for a new release and other files, which are mostly self-explanatory by name. 

## Adding a new architecture
### Constants
Since none of RISC-V is supported, one needs to define the constants like modes, architecture, relocations, etc., that do not contain any programming logic, but are necessary for later use:
- include/keystone/keystone.h
- include/keystone/riscv.h
- llvm/CMakeLists.txt
- llvm/include/llvm/ADT/Triple.h
- llvm/include/llvm/MC/MCFixup.h
- llvm/include/llvm/MC/MCInstrDesc.h
- llvm/include/llvm/Support/ELF.h
- llvm/include/llvm/Support/ELFRelocs/RISCV.def
- llvm/keystone/CMakeLists.txt 
- llvm/keystone/ks_priv.h
- llvm/lib/Target/LLVMBuild.txt

If these constants are not copy-paste from other architectures, refer to the new llvm version's files to see the intended names and values.

### Kstool
Include RISC-V support to the kstool for command line tool support and help tips in:
- kstool/kstool.cpp

### Processing of RISC-V options
Each architecture and each mode has different options that need to get parsed outside of `llvm/lib/Target/<arch>` directory and set constants for later use:
- llvm/include/llvm/Object/ELFObjectFile.h
- llvm/keystone/ks.cpp
- llvm/lib/Support/Triple.cpp

### Expanding MCAsmBackend
Because the MCAsmBackend constructor does not allow passing the subtarget info and target options that the new llvm versions require for the backend construction, a new backend constructor must be created (in order to prevent having to change the other architecture's code). This is supported in `llvm/include/llvm/Support/TargetRegistry.h`. 

### Expanding core llvm code (llvm/include/llvm)
Adding the required supporting functions that are used in the newer llvm files but do not yet exist in Keystone's version of llvm:
- llvm/include/llvm/ADT/StringRef.h
- llvm/include/llvm/ADT/Triple.h
- llvm/include/llvm/MC/MCFixup.h
- llvm/include/llvm/MC/MCInst.h
- llvm/include/llvm/MC/MCInstrDesc.h
- llvm/include/llvm/MC/MCObjectFileInfo.h
- llvm/include/llvm/MC/MCParser/MCTargetAsmParser.h
- llvm/include/llvm/MC/MCSubtargetInfo.h
- llvm/lib/MC/MCInst.cpp
- llvm/lib/MC/MCParser/MCTargetAsmParser.cpp

### FeatureBitset
FeatureBitset is a class for storing features of an architecture. Instead of having an unsigned integer variable and then using bitwise operators on it, this class extends the standard bitset class from c++ which comes with many built-in methods (https://en.cppreference.com/w/cpp/utility/bitset). Keystone does not use one or the other exclusively in other architectures, but the new llvm versions do. I have added the support methods with added suffix FB to Keystone to support this. RISC-V part of Keystone also uses exclusively FeatureBitsets to increase the understandability of code and bring more consistency. If a big update to Keystone could be made - i.e. rebuilding Keystone from a newer llvm version as base, this should become the standard.

## RISCV folder - llvm/lib/Target/RISCV
This is the "meat" of the implementation, so I will explain each folder and file separately. To aquire the base files from llvm (in my case llvm v9.0.1), one has to download the llvm release and build it, then copy the `llvm/lib/Target/RISCV` folder into the same of Keystone, then go to the llvm v9.0.1's build/lib/Target/RISCV and copy \*.inc files to `llvm/lib/Target/RISCV` folder of Keystone.

>  A note when building llvm v9.0.1 specifically, `#include <limits>` is missing in `llvm/utils/benchmark/src/benchmark_register.h` and thus the build errors out. Add it to the top of the file to get llvm v9.0.1 to build correctly.

The \*.inc files are created from table description (\*.td) files, which describe everything about an ISA, from instruction syntax to operand restrictions. Using the TableGen tool, the default llvm build creates these files for us. This way we do not have to use the tool itself and configure exactly where the dependencies are. The resulting \*.inc files are written in C and should generally not be altered, however since Keystone keeps compilation times in mind, these files need to be pruned to minimal amount of lines, deleting any unused code. 

Before reading the code, I recommend getting familiar with the following concepts in llvm:

- MCInst  
    - the class that represents an instruction with operands
- Instruction Printer
	- implements MCInstPrinter API
	- given a single MCInst, it formats and emits the textual representation to a raw_ostream
- Instruction Encoder
	- implements MCCodeEmitter API
	- transforms an MCInst into a series of bytes and a list of relocations
- Instruction Parser
	- lexers and parsers implement TargetAsmParser API 
	- once an instruction is parsed, we get opcode + list of operands 
	- matching API is exposed by parser
	- if need be, the instructions are held in a more abstract than MCInst representation until relaxation (=fixup) is performed 
- Instruction Decoder
	- implements MCDisassembler API- abstract series of bytes into a MCInst and a size 
	- not so useful for Keystone
- Assembly Parser 
	- handles all directives and everything else in a .s file that is not an instruction (should not be confused with TargetAsmParser API)
- MCStreamer API
	- assembler API that takes one virtual method per directive and one EmitInstruction method with MCInst as input 
- Assembler Backend
	- one implementation of the MCStreamer API (with MCAsmStreamer) 
	- implements relaxation
	- lays out fragments into sections, resolves instructions with symbolic operands to immediates and passes this info off to a .o object file


### llvm/lib/Target/RISCV files
In the root folder, there are:
- llvm/lib/Target/RISCV/CMakeLists.txt (empty because TableGen was already performed beforehand), 
- llvm/lib/Target/RISCV/LLVMBuild.txt (copied from LLVM but only keeping component_0),
- llvm/lib/Target/RISCV/RISCV.h (defines base classes)
- llvm/lib/Target/RISCV/RISCVGenAsmMatcher.inc:
    - ComputeAvailableFeaturesFB: computes the available features from the FeatureBitset (check the FeatureBitset chapter to see why this is important).
    - convertToMCInst: uses the instruction 'Kind' to set types of operands for the MCInst object.
    - convertToMapAndConstraints: checks the constraints for each operand (register, immediate, no constraint).
    - MatchInstructionImpl: checks the current available features, available mnemonic ranges, validates the classes of all operands, matches an instruction to the correct MCInst and returns it.
    - Other than these main function implementations, there are also many helper functions that parse the register names, apply aliases, check features and others. This file also contains conversion tables, mnemonic tables, defines the restraints for each instruction and all its allowed formats.  
- llvm/lib/Target/RISCV/RISCVGenCompressInstEmitter.inc: 
    - Responsible for compressing instructions (whenever possible) from 4 bytes (default) to 2 bytes. 
- llvm/lib/Target/RISCV/RISCVGenInstrInfo.inc:
    - Instruction and operand constants, does not need changing.
- llvm/lib/Target/RISCV/RISCVGenMCCodeEmitter.inc:
    - Matches MCInst and emits machine code. Also contains constants for mnemonics' machine code.
- llvm/lib/Target/RISCV/RISCVGenSubtargetInfo.inc:
    - Defines all possible features (=extensions), CPU types and which features each CPU supports.  
- llvm/lib/Target/RISCV/RISCVGenSystemOperands.inc:
    - Defines constants for system 

### llvm/lib/Target/RISCV/AsmParser files
- llvm/lib/Target/RISCV/AsmParser/CMakeLists.txt:
    - Copied from llvm.
- llvm/lib/Target/RISCV/AsmParser/LLVMBuild.txt:
    - Copied from llvm.
- llvm/lib/Target/RISCV/AsmParser/RISCVAsmParser.cpp:
    - Extends the MCTargetAsmParser base class.
    - The target assembly parser handles everything in a .s file into MCInst instructions, uses RISCVGenAsmMatcher.inc functionality to do so.
    - In many functions, an error code for Keystone must be added, since it is configured to return an error value instead of raising an error to prevent crashing a test program in favor of failing that specific instruction.
    - Setting and computing the available features are completed on FeatureBitset and have as such appended the FB suffix to distinguish them from computing the uint8_t vector.  
    - Call the streamer API correctly. 

### llvm/lib/Target/RISCV/MCTargetDesc files
- llvm/lib/Target/RISCV/MCTargetDesc/CMakeLists.txt:
    - Copied from llvm.
- llvm/lib/Target/RISCV/MCTargetDesc/LLVMBuild.txt:
    - Copied from llvm.
- llvm/lib/Target/RISCV/MCTargetDesc/RISCVAsmBackend.cpp:
    - In this file, the functionality for creating a MCAsmBackend for RISC-V resides. Because the newer backend version is created differently from how the Keystone's version llvm created it, the input parameters are changed to match the expanded MCAsmBackend as already stated higher up in this document. This is because the subtarget info and target options need to be parsed from the current MCAsmBackend by the ELFStreamer and AsmParser.
    - Change the write statements to Keystone's write method (for nop instructions).
    - Add KsError to applyFixup to return errors gracefully.
- llvm/lib/Target/RISCV/MCTargetDesc/RISCVAsmBackend.h:
    - Change the function and the RISCVAsmBackend constructor signatures to match RISCVAsmBackend. 
- llvm/lib/Target/RISCV/MCTargetDesc/RISCVELFObjectWriter.cpp:
    - Change the createRISCVELFObjectWriter to use the correct params (always have little endian in our case since both generic targets are little endian).
- llvm/lib/Target/RISCV/MCTargetDesc/RISCVELFStreamer.cpp:
    - Copied from llvm; Since Keystone doesn't have the ABI passed to RISCVTargetELFStreamer, we need to get it from the backend. I used this method to get the assembler and backend in the AsmParser in ParseInstruction.
    - The eflags are set in this file depending on the ABI used.  
- llvm/lib/Target/RISCV/MCTargetDesc/RISCVELFStreamer.h:
    - Copied from llvm; just the header file for .cpp file above.
- llvm/lib/Target/RISCV/MCTargetDesc/RISCVFixupKinds.h:
    - Copied from llvm; defines fixup kinds.
- llvm/lib/Target/RISCV/MCTargetDesc/RISCVMCAsmInfo.cpp:
    - Defines basic information about the assembly architecture.
    - Added correct PointerSize since it is used in other parts of code, PrivateGlobalPrefix and PrivateLabelPrefix from new llvm version. 
- llvm/lib/Target/RISCV/MCTargetDesc/RISCVMCAsmInfo.h:
    - Copied from llvm; just the header file for .cpp file above.
- llvm/lib/Target/RISCV/MCTargetDesc/RISCVMCCodeEmitter.cpp:
    - Include KsError propagation into the relevant functions, change the writes to Keystone syntax.
    - This file creates the MCCodeEmitter class that emits machine code from a MCInst object (with the help from RISCVGenMCCodeEmitter.inc) as well as parses the special instruction cases (TPRel add, pseudo tail, ...).
- llvm/lib/Target/RISCV/MCTargetDesc/RISCVMCExpr.cpp:
    - Evaluate functions for the symbol modifiers for RISCV - can be found at [https://sourceware.org/binutils/docs-2.35/as/RISC_002dV_002dModifiers.html](https://sourceware.org/binutils/docs-2.35/as/RISC_002dV_002dModifiers.html).
- llvm/lib/Target/RISCV/MCTargetDesc/RISCVMCExpr.h:
    - Copied from llvm; just the header file for .cpp file above.
- llvm/lib/Target/RISCV/MCTargetDesc/RISCVMCTargetDesc.cpp:
    - Initializes all the needed classes in the target registry. Since our AsmBackend needs extra parameters for initialization, this has a different constructor registered. Also need to initialize the AsmTargetStreamer with the right parameters.
- llvm/lib/Target/RISCV/MCTargetDesc/RISCVMCTargetDesc.h:
    - Copied from llvm; just the header file for .cpp file above.
- llvm/lib/Target/RISCV/MCTargetDesc/RISCVTargetStreamer.cpp:
    - Copied from llvm; emits directives for different options that we have (more about this can be found at [https://sourceware.org/binutils/docs-2.31/as/RISC_002dV_002dDirectives.html#RISC_002dV_002dDirectives](https://sourceware.org/binutils/docs-2.31/as/RISC_002dV_002dDirectives.html#RISC_002dV_002dDirectives).
- llvm/lib/Target/RISCV/MCTargetDesc/RISCVTargetStreamer.h:
    - Copied from llvm; just the header file for .cpp file above.

### llvm/lib/Target/RISCV/TargetInfo files
- llvm/lib/Target/RISCV/TargetInfo/CMakeLists.txt:
    - Copied from llvm.
- llvm/lib/Target/RISCV/TargetInfo/LLVMBuild.txt:
    - Copied from llvm.
- llvm/lib/Target/RISCV/TargetInfo/RISCVTargetInfo.cpp:
    - Changed to access the targets directly instead of with getters, since this is how Keystone does it. In the future, it would be good to change everything to getters but for the sake of code consistency, it is better to keep everything uniform for now.
- llvm/lib/Target/RISCV/TargetInfo/RISCVTargetInfo.h:
    - Remove the getter definitions to match the .cpp file above.

### llvm/lib/Target/RISCV/Utils files
- llvm/lib/Target/RISCV/Utils/CMakeLists.txt:
    - Copied from llvm.
- llvm/lib/Target/RISCV/Utils/LLVMBuild.txt:
    - Copied from llvm.
-  llvm/lib/Target/RISCV/Utils/RISCVBaseInfo.cpp:
    -  Copied from llvm; Initializes target ABI.
-  llvm/lib/Target/RISCV/Utils/RISCVBaseInfo.h:
    -  Copied from llvm; Defines constants for instruction formats, symbol modifiers, fence options, rounding modes, ABIs and helper functions.
-  llvm/lib/Target/RISCV/Utils/RISCVMatInt.cpp:
    -  Copied from llvm; Helper functions for instruction sequeces generated by pseudo instructions.
-  llvm/lib/Target/RISCV/Utils/RISCVMatInt.h:
    -  Copied from llvm; just the header file for .cpp file above (contains a description of what each function does).


## Build bindings
Keystone has autogenerate-able language bindings for python, ruby, rust, go, powershell, nodejs. After adding support for RISC-V in 
- include/keystone/keystone.h, 
- bindings/const\_generator.py 
- /python/setup.py and 
- bindings/python/keystone/keystone\_const.py, 

run the following commands to update the bindings:
```bash
# cwd == build
cd ../bindings
make all
```

To install the pip package for using Keystone in python, move into `bindings/python` directory and install for python with the following:
```bash
make install
```
Or alternatively for python3:
```bash
make install3
```
Pay attention to `bindings/pyton/Makefile` however, as python versions differ. Since python 3.11.\*, a user cannot manually install system wide pip packages (Debian). One option is to run the install commands from the Makefile install command yourself in a virtual environment, the second one is to change the Makefile itself to do the same and the last one is to use a python version 3.10.\* and lower. 

Additionally, one may have to add the following to the top of the `bindings/python/Makefile` if they want to have a system-wide pip install:
```bash
DESTDIR = /
```

## Build the project
All that's left is to build and run Keystone. Follow the instructions in `keystone/docs/COMPILE.md` to build the project, then test it. For testing Keystone and its python bindings, there is a documentation page at [https://github.com/null-cell/keystone-riscv-testing](https://github.com/null-cell/keystone-riscv-testing)



