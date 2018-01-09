/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Subtarget Enumeration Source Fragment                                      *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/


#ifdef GET_SUBTARGETINFO_ENUM
#undef GET_SUBTARGETINFO_ENUM
namespace llvm_ks {
namespace X86 {
enum : uint64_t {
  Feature3DNow = 0,
  Feature3DNowA = 1,
  Feature64Bit = 2,
  FeatureADX = 3,
  FeatureAES = 4,
  FeatureAVX = 5,
  FeatureAVX2 = 6,
  FeatureAVX512 = 7,
  FeatureBMI = 8,
  FeatureBMI2 = 9,
  FeatureBWI = 10,
  FeatureCDI = 11,
  FeatureCLFLUSHOPT = 12,
  FeatureCLWB = 13,
  FeatureCMOV = 14,
  FeatureCMPXCHG16B = 15,
  FeatureCallRegIndirect = 16,
  FeatureDQI = 17,
  FeatureERI = 18,
  FeatureF16C = 19,
  FeatureFMA = 20,
  FeatureFMA4 = 21,
  FeatureFSGSBase = 22,
  FeatureFXSR = 23,
  FeatureHLE = 24,
  FeatureIFMA = 25,
  FeatureINVPCID = 26,
  FeatureLAHFSAHF = 27,
  FeatureLEAForSP = 28,
  FeatureLEAUsesAG = 29,
  FeatureLZCNT = 30,
  FeatureMMX = 31,
  FeatureMOVBE = 32,
  FeatureMPX = 33,
  FeaturePCLMUL = 34,
  FeaturePCOMMIT = 35,
  FeaturePFI = 36,
  FeaturePKU = 37,
  FeaturePOPCNT = 38,
  FeaturePREFETCHWT1 = 39,
  FeaturePRFCHW = 40,
  FeaturePadShortFunctions = 41,
  FeatureRDRAND = 42,
  FeatureRDSEED = 43,
  FeatureRTM = 44,
  FeatureSGX = 45,
  FeatureSHA = 46,
  FeatureSMAP = 47,
  FeatureSSE1 = 48,
  FeatureSSE2 = 49,
  FeatureSSE3 = 50,
  FeatureSSE4A = 51,
  FeatureSSE41 = 52,
  FeatureSSE42 = 53,
  FeatureSSEUnalignedMem = 54,
  FeatureSSSE3 = 55,
  FeatureSlowBTMem = 56,
  FeatureSlowDivide32 = 57,
  FeatureSlowDivide64 = 58,
  FeatureSlowIncDec = 59,
  FeatureSlowLEA = 60,
  FeatureSlowSHLD = 61,
  FeatureSlowUAMem16 = 62,
  FeatureSlowUAMem32 = 63,
  FeatureSoftFloat = 64,
  FeatureTBM = 65,
  FeatureVBMI = 66,
  FeatureVLX = 67,
  FeatureVMFUNC = 68,
  FeatureXOP = 69,
  FeatureXSAVE = 70,
  FeatureXSAVEC = 71,
  FeatureXSAVEOPT = 72,
  FeatureXSAVES = 73,
  Mode16Bit = 74,
  Mode32Bit = 75,
  Mode64Bit = 76,
  ProcIntelAtom = 77,
  ProcIntelBDW = 78,
  ProcIntelCNL = 79,
  ProcIntelHSW = 80,
  ProcIntelIVB = 81,
  ProcIntelSKL = 82,
  ProcIntelSKX = 83,
  ProcIntelSLM = 84,
  ProcIntelSNB = 85
};
}
} // end llvm namespace
#endif // GET_SUBTARGETINFO_ENUM


#ifdef GET_SUBTARGETINFO_MC_DESC
#undef GET_SUBTARGETINFO_MC_DESC
namespace llvm_ks {
// Sorted (by key) array of values for CPU features.
extern const llvm_ks::SubtargetFeatureKV X86FeatureKV[] = {
  { "16bit-mode", "16-bit mode (i8086)", { X86::Mode16Bit }, { } },
  { "32bit-mode", "32-bit mode (80386)", { X86::Mode32Bit }, { } },
  { "3dnow", "Enable 3DNow! instructions", { X86::Feature3DNow }, { X86::FeatureMMX } },
  { "3dnowa", "Enable 3DNow! Athlon instructions", { X86::Feature3DNowA }, { X86::Feature3DNow } },
  { "64bit", "Support 64-bit instructions", { X86::Feature64Bit }, { X86::FeatureCMOV } },
  { "64bit-mode", "64-bit mode (x86_64)", { X86::Mode64Bit }, { } },
  { "adx", "Support ADX instructions", { X86::FeatureADX }, { } },
  { "aes", "Enable AES instructions", { X86::FeatureAES }, { X86::FeatureSSE2 } },
  { "atom", "Intel Atom processors", { X86::ProcIntelAtom }, { } },
  { "avx", "Enable AVX instructions", { X86::FeatureAVX }, { X86::FeatureSSE42 } },
  { "avx2", "Enable AVX2 instructions", { X86::FeatureAVX2 }, { X86::FeatureAVX } },
  { "avx512bw", "Enable AVX-512 Byte and Word Instructions", { X86::FeatureBWI }, { X86::FeatureAVX512 } },
  { "avx512cd", "Enable AVX-512 Conflict Detection Instructions", { X86::FeatureCDI }, { X86::FeatureAVX512 } },
  { "avx512dq", "Enable AVX-512 Doubleword and Quadword Instructions", { X86::FeatureDQI }, { X86::FeatureAVX512 } },
  { "avx512er", "Enable AVX-512 Exponential and Reciprocal Instructions", { X86::FeatureERI }, { X86::FeatureAVX512 } },
  { "avx512f", "Enable AVX-512 instructions", { X86::FeatureAVX512 }, { X86::FeatureAVX2 } },
  { "avx512pf", "Enable AVX-512 PreFetch Instructions", { X86::FeaturePFI }, { X86::FeatureAVX512 } },
  { "avx512vbmi", "Enable AVX-512 Vector Bit Manipulation Instructions", { X86::FeatureVBMI }, { X86::FeatureAVX512 } },
  { "avx512vl", "Enable AVX-512 Vector Length eXtensions", { X86::FeatureVLX }, { X86::FeatureAVX512 } },
  { "bdw", " Intel Broadwell Processor", { X86::ProcIntelBDW }, { X86::ProcIntelHSW, X86::FeatureADX, X86::FeatureRDSEED, X86::FeatureSMAP } },
  { "bmi", "Support BMI instructions", { X86::FeatureBMI }, { } },
  { "bmi2", "Support BMI2 instructions", { X86::FeatureBMI2 }, { } },
  { "call-reg-indirect", "Call register indirect", { X86::FeatureCallRegIndirect }, { } },
  { "clflushopt", "Flush A Cache Line Optimized", { X86::FeatureCLFLUSHOPT }, { } },
  { "clwb", "Cache Line Write Back", { X86::FeatureCLWB }, { } },
  { "cmov", "Enable conditional move instructions", { X86::FeatureCMOV }, { } },
  { "cnl", " Intel Cannonlake Processor", { X86::ProcIntelCNL }, { X86::ProcIntelSKX, X86::FeatureVBMI, X86::FeatureIFMA, X86::FeatureSHA } },
  { "cx16", "64-bit with cmpxchg16b", { X86::FeatureCMPXCHG16B }, { X86::Feature64Bit } },
  { "f16c", "Support 16-bit floating point conversion instructions", { X86::FeatureF16C }, { X86::FeatureAVX } },
  { "fma", "Enable three-operand fused multiple-add", { X86::FeatureFMA }, { X86::FeatureAVX } },
  { "fma4", "Enable four-operand fused multiple-add", { X86::FeatureFMA4 }, { X86::FeatureAVX, X86::FeatureSSE4A } },
  { "fsgsbase", "Support FS/GS Base instructions", { X86::FeatureFSGSBase }, { } },
  { "fxsr", "Support fxsave/fxrestore instructions", { X86::FeatureFXSR }, { } },
  { "hle", "Support HLE", { X86::FeatureHLE }, { } },
  { "hsw", " Intel Haswell Processor", { X86::ProcIntelHSW }, { X86::ProcIntelIVB, X86::FeatureAVX2, X86::FeatureBMI, X86::FeatureBMI2, X86::FeatureFMA, X86::FeatureLZCNT, X86::FeatureMOVBE, X86::FeatureINVPCID, X86::FeatureVMFUNC, X86::FeatureRTM, X86::FeatureHLE, X86::FeatureSlowIncDec } },
  { "idivl-to-divb", "Use 8-bit divide for positive values less than 256", { X86::FeatureSlowDivide32 }, { } },
  { "idivq-to-divw", "Use 16-bit divide for positive values less than 65536", { X86::FeatureSlowDivide64 }, { } },
  { "ifma", "Enable AVX-512 Integer Fused Multiple-Add", { X86::FeatureIFMA }, { X86::FeatureAVX512 } },
  { "invpcid", "Invalidate Process-Context Identifier", { X86::FeatureINVPCID }, { } },
  { "ivb", " Intel IvyBridge Processor", { X86::ProcIntelIVB }, { X86::ProcIntelSNB, X86::FeatureRDRAND, X86::FeatureF16C, X86::FeatureFSGSBase } },
  { "lea-sp", "Use LEA for adjusting the stack pointer", { X86::FeatureLEAForSP }, { } },
  { "lea-uses-ag", "LEA instruction needs inputs at AG stage", { X86::FeatureLEAUsesAG }, { } },
  { "lzcnt", "Support LZCNT instruction", { X86::FeatureLZCNT }, { } },
  { "mmx", "Enable MMX instructions", { X86::FeatureMMX }, { } },
  { "movbe", "Support MOVBE instruction", { X86::FeatureMOVBE }, { } },
  { "mpx", "Support MPX instructions", { X86::FeatureMPX }, { } },
  { "pad-short-functions", "Pad short functions", { X86::FeaturePadShortFunctions }, { } },
  { "pclmul", "Enable packed carry-less multiplication instructions", { X86::FeaturePCLMUL }, { X86::FeatureSSE2 } },
  { "pcommit", "Enable Persistent Commit", { X86::FeaturePCOMMIT }, { } },
  { "pku", "Enable protection keys", { X86::FeaturePKU }, { } },
  { "popcnt", "Support POPCNT instruction", { X86::FeaturePOPCNT }, { } },
  { "prefetchwt1", "Prefetch with Intent to Write and T1 Hint", { X86::FeaturePREFETCHWT1 }, { } },
  { "prfchw", "Support PRFCHW instructions", { X86::FeaturePRFCHW }, { } },
  { "rdrnd", "Support RDRAND instruction", { X86::FeatureRDRAND }, { } },
  { "rdseed", "Support RDSEED instruction", { X86::FeatureRDSEED }, { } },
  { "rtm", "Support RTM instructions", { X86::FeatureRTM }, { } },
  { "sahf", "Support LAHF and SAHF instructions", { X86::FeatureLAHFSAHF }, { } },
  { "sgx", "Enable Software Guard Extensions", { X86::FeatureSGX }, { } },
  { "sha", "Enable SHA instructions", { X86::FeatureSHA }, { X86::FeatureSSE2 } },
  { "skl", " Intel Skylake Client Processor", { X86::ProcIntelSKL }, { X86::ProcIntelBDW, X86::FeatureMPX, X86::FeatureXSAVEC, X86::FeatureXSAVES, X86::FeatureSGX, X86::FeatureCLFLUSHOPT } },
  { "skx", " Intel Skylake Server Processor", { X86::ProcIntelSKX }, { X86::ProcIntelSKL, X86::FeatureAVX512, X86::FeatureCDI, X86::FeatureDQI, X86::FeatureBWI, X86::FeatureVLX, X86::FeaturePKU, X86::FeaturePCOMMIT, X86::FeatureCLWB } },
  { "slm", "Intel Silvermont processors", { X86::ProcIntelSLM }, { } },
  { "slow-bt-mem", "Bit testing of memory is slow", { X86::FeatureSlowBTMem }, { } },
  { "slow-incdec", "INC and DEC instructions are slower than ADD and SUB", { X86::FeatureSlowIncDec }, { } },
  { "slow-lea", "LEA instruction with certain arguments is slow", { X86::FeatureSlowLEA }, { } },
  { "slow-shld", "SHLD instruction is slow", { X86::FeatureSlowSHLD }, { } },
  { "slow-unaligned-mem-16", "Slow unaligned 16-byte memory access", { X86::FeatureSlowUAMem16 }, { } },
  { "slow-unaligned-mem-32", "Slow unaligned 32-byte memory access", { X86::FeatureSlowUAMem32 }, { } },
  { "smap", "Supervisor Mode Access Protection", { X86::FeatureSMAP }, { } },
  { "snb", " Intel SandyBridge Processor", { X86::ProcIntelSNB }, { X86::FeatureMMX, X86::FeatureAVX, X86::FeatureFXSR, X86::FeatureCMPXCHG16B, X86::FeaturePOPCNT, X86::FeatureAES, X86::FeaturePCLMUL, X86::FeatureXSAVE, X86::FeatureXSAVEOPT, X86::FeatureLAHFSAHF } },
  { "soft-float", "Use software floating point features.", { X86::FeatureSoftFloat }, { } },
  { "sse", "Enable SSE instructions", { X86::FeatureSSE1 }, { X86::FeatureCMOV } },
  { "sse-unaligned-mem", "Allow unaligned memory operands with SSE instructions", { X86::FeatureSSEUnalignedMem }, { } },
  { "sse2", "Enable SSE2 instructions", { X86::FeatureSSE2 }, { X86::FeatureSSE1 } },
  { "sse3", "Enable SSE3 instructions", { X86::FeatureSSE3 }, { X86::FeatureSSE2 } },
  { "sse4.1", "Enable SSE 4.1 instructions", { X86::FeatureSSE41 }, { X86::FeatureSSSE3 } },
  { "sse4.2", "Enable SSE 4.2 instructions", { X86::FeatureSSE42 }, { X86::FeatureSSE41 } },
  { "sse4a", "Support SSE 4a instructions", { X86::FeatureSSE4A }, { X86::FeatureSSE3 } },
  { "ssse3", "Enable SSSE3 instructions", { X86::FeatureSSSE3 }, { X86::FeatureSSE3 } },
  { "tbm", "Enable TBM instructions", { X86::FeatureTBM }, { } },
  { "vmfunc", "VM Functions", { X86::FeatureVMFUNC }, { } },
  { "xop", "Enable XOP instructions", { X86::FeatureXOP }, { X86::FeatureFMA4 } },
  { "xsave", "Support xsave instructions", { X86::FeatureXSAVE }, { } },
  { "xsavec", "Support xsavec instructions", { X86::FeatureXSAVEC }, { } },
  { "xsaveopt", "Support xsaveopt instructions", { X86::FeatureXSAVEOPT }, { } },
  { "xsaves", "Support xsaves instructions", { X86::FeatureXSAVES }, { } }
};

// Sorted (by key) array of values for CPU subtype.
extern const llvm_ks::SubtargetFeatureKV X86SubTypeKV[] = {
  { "amdfam10", "Select the amdfam10 processor", { X86::FeatureSSE4A, X86::Feature3DNowA, X86::FeatureFXSR, X86::FeatureCMPXCHG16B, X86::FeatureLZCNT, X86::FeaturePOPCNT, X86::FeatureSlowBTMem, X86::FeatureSlowSHLD, X86::FeatureLAHFSAHF }, { } },
  { "athlon", "Select the athlon processor", { X86::FeatureSlowUAMem16, X86::Feature3DNowA, X86::FeatureSlowBTMem, X86::FeatureSlowSHLD }, { } },
  { "athlon-4", "Select the athlon-4 processor", { X86::FeatureSlowUAMem16, X86::FeatureSSE1, X86::Feature3DNowA, X86::FeatureFXSR, X86::FeatureSlowBTMem, X86::FeatureSlowSHLD }, { } },
  { "athlon-fx", "Select the athlon-fx processor", { X86::FeatureSlowUAMem16, X86::FeatureSSE2, X86::Feature3DNowA, X86::FeatureFXSR, X86::Feature64Bit, X86::FeatureSlowBTMem, X86::FeatureSlowSHLD }, { } },
  { "athlon-mp", "Select the athlon-mp processor", { X86::FeatureSlowUAMem16, X86::FeatureSSE1, X86::Feature3DNowA, X86::FeatureFXSR, X86::FeatureSlowBTMem, X86::FeatureSlowSHLD }, { } },
  { "athlon-tbird", "Select the athlon-tbird processor", { X86::FeatureSlowUAMem16, X86::Feature3DNowA, X86::FeatureSlowBTMem, X86::FeatureSlowSHLD }, { } },
  { "athlon-xp", "Select the athlon-xp processor", { X86::FeatureSlowUAMem16, X86::FeatureSSE1, X86::Feature3DNowA, X86::FeatureFXSR, X86::FeatureSlowBTMem, X86::FeatureSlowSHLD }, { } },
  { "athlon64", "Select the athlon64 processor", { X86::FeatureSlowUAMem16, X86::FeatureSSE2, X86::Feature3DNowA, X86::FeatureFXSR, X86::Feature64Bit, X86::FeatureSlowBTMem, X86::FeatureSlowSHLD }, { } },
  { "athlon64-sse3", "Select the athlon64-sse3 processor", { X86::FeatureSlowUAMem16, X86::FeatureSSE3, X86::Feature3DNowA, X86::FeatureFXSR, X86::FeatureCMPXCHG16B, X86::FeatureSlowBTMem, X86::FeatureSlowSHLD }, { } },
  { "atom", "Select the atom processor", { X86::ProcIntelAtom, X86::FeatureSlowUAMem16, X86::FeatureMMX, X86::FeatureSSSE3, X86::FeatureFXSR, X86::FeatureCMPXCHG16B, X86::FeatureMOVBE, X86::FeatureSlowBTMem, X86::FeatureLEAForSP, X86::FeatureSlowDivide32, X86::FeatureSlowDivide64, X86::FeatureCallRegIndirect, X86::FeatureLEAUsesAG, X86::FeaturePadShortFunctions, X86::FeatureLAHFSAHF }, { } },
  { "barcelona", "Select the barcelona processor", { X86::FeatureSSE4A, X86::Feature3DNowA, X86::FeatureFXSR, X86::FeatureCMPXCHG16B, X86::FeatureLZCNT, X86::FeaturePOPCNT, X86::FeatureSlowBTMem, X86::FeatureSlowSHLD, X86::FeatureLAHFSAHF }, { } },
  { "bdver1", "Select the bdver1 processor", { X86::FeatureXOP, X86::FeatureFMA4, X86::FeatureCMPXCHG16B, X86::FeatureAES, X86::FeaturePRFCHW, X86::FeaturePCLMUL, X86::FeatureMMX, X86::FeatureAVX, X86::FeatureFXSR, X86::FeatureSSE4A, X86::FeatureLZCNT, X86::FeaturePOPCNT, X86::FeatureXSAVE, X86::FeatureSlowSHLD, X86::FeatureLAHFSAHF }, { } },
  { "bdver2", "Select the bdver2 processor", { X86::FeatureXOP, X86::FeatureFMA4, X86::FeatureCMPXCHG16B, X86::FeatureAES, X86::FeaturePRFCHW, X86::FeaturePCLMUL, X86::FeatureMMX, X86::FeatureAVX, X86::FeatureFXSR, X86::FeatureSSE4A, X86::FeatureF16C, X86::FeatureLZCNT, X86::FeaturePOPCNT, X86::FeatureXSAVE, X86::FeatureBMI, X86::FeatureTBM, X86::FeatureFMA, X86::FeatureSlowSHLD, X86::FeatureLAHFSAHF }, { } },
  { "bdver3", "Select the bdver3 processor", { X86::FeatureXOP, X86::FeatureFMA4, X86::FeatureCMPXCHG16B, X86::FeatureAES, X86::FeaturePRFCHW, X86::FeaturePCLMUL, X86::FeatureMMX, X86::FeatureAVX, X86::FeatureFXSR, X86::FeatureSSE4A, X86::FeatureF16C, X86::FeatureLZCNT, X86::FeaturePOPCNT, X86::FeatureXSAVE, X86::FeatureBMI, X86::FeatureTBM, X86::FeatureFMA, X86::FeatureXSAVEOPT, X86::FeatureSlowSHLD, X86::FeatureFSGSBase, X86::FeatureLAHFSAHF }, { } },
  { "bdver4", "Select the bdver4 processor", { X86::FeatureMMX, X86::FeatureAVX2, X86::FeatureFXSR, X86::FeatureXOP, X86::FeatureFMA4, X86::FeatureCMPXCHG16B, X86::FeatureAES, X86::FeaturePRFCHW, X86::FeaturePCLMUL, X86::FeatureF16C, X86::FeatureLZCNT, X86::FeaturePOPCNT, X86::FeatureXSAVE, X86::FeatureBMI, X86::FeatureBMI2, X86::FeatureTBM, X86::FeatureFMA, X86::FeatureXSAVEOPT, X86::FeatureFSGSBase, X86::FeatureLAHFSAHF }, { } },
  { "bonnell", "Select the bonnell processor", { X86::ProcIntelAtom, X86::FeatureSlowUAMem16, X86::FeatureMMX, X86::FeatureSSSE3, X86::FeatureFXSR, X86::FeatureCMPXCHG16B, X86::FeatureMOVBE, X86::FeatureSlowBTMem, X86::FeatureLEAForSP, X86::FeatureSlowDivide32, X86::FeatureSlowDivide64, X86::FeatureCallRegIndirect, X86::FeatureLEAUsesAG, X86::FeaturePadShortFunctions, X86::FeatureLAHFSAHF }, { } },
  { "broadwell", "Select the broadwell processor", { X86::ProcIntelBDW }, { } },
  { "btver1", "Select the btver1 processor", { X86::FeatureMMX, X86::FeatureSSSE3, X86::FeatureSSE4A, X86::FeatureFXSR, X86::FeatureCMPXCHG16B, X86::FeaturePRFCHW, X86::FeatureLZCNT, X86::FeaturePOPCNT, X86::FeatureXSAVE, X86::FeatureSlowSHLD, X86::FeatureLAHFSAHF }, { } },
  { "btver2", "Select the btver2 processor", { X86::FeatureMMX, X86::FeatureAVX, X86::FeatureFXSR, X86::FeatureSSE4A, X86::FeatureCMPXCHG16B, X86::FeaturePRFCHW, X86::FeatureAES, X86::FeaturePCLMUL, X86::FeatureBMI, X86::FeatureF16C, X86::FeatureMOVBE, X86::FeatureLZCNT, X86::FeaturePOPCNT, X86::FeatureXSAVE, X86::FeatureXSAVEOPT, X86::FeatureSlowSHLD, X86::FeatureLAHFSAHF }, { } },
  { "c3", "Select the c3 processor", { X86::FeatureSlowUAMem16, X86::Feature3DNow }, { } },
  { "c3-2", "Select the c3-2 processor", { X86::FeatureSlowUAMem16, X86::FeatureMMX, X86::FeatureSSE1, X86::FeatureFXSR }, { } },
  { "cannonlake", "Select the cannonlake processor", { X86::ProcIntelCNL }, { } },
  { "cnl", "Select the cnl processor", { X86::ProcIntelCNL }, { } },
  { "core-avx-i", "Select the core-avx-i processor", { X86::ProcIntelIVB, X86::FeatureSlowBTMem, X86::FeatureSlowUAMem32 }, { } },
  { "core-avx2", "Select the core-avx2 processor", { X86::ProcIntelHSW }, { } },
  { "core2", "Select the core2 processor", { X86::FeatureSlowUAMem16, X86::FeatureMMX, X86::FeatureSSSE3, X86::FeatureFXSR, X86::FeatureCMPXCHG16B, X86::FeatureSlowBTMem, X86::FeatureLAHFSAHF }, { } },
  { "corei7", "Select the corei7 processor", { X86::FeatureMMX, X86::FeatureSSE42, X86::FeatureFXSR, X86::FeatureCMPXCHG16B, X86::FeatureSlowBTMem, X86::FeaturePOPCNT, X86::FeatureLAHFSAHF }, { } },
  { "corei7-avx", "Select the corei7-avx processor", { X86::ProcIntelSNB, X86::FeatureSlowBTMem, X86::FeatureSlowUAMem32 }, { } },
  { "generic", "Select the generic processor", { X86::FeatureSlowUAMem16 }, { } },
  { "geode", "Select the geode processor", { X86::FeatureSlowUAMem16, X86::Feature3DNowA }, { } },
  { "haswell", "Select the haswell processor", { X86::ProcIntelHSW }, { } },
  { "i386", "Select the i386 processor", { X86::FeatureSlowUAMem16 }, { } },
  { "i486", "Select the i486 processor", { X86::FeatureSlowUAMem16 }, { } },
  { "i586", "Select the i586 processor", { X86::FeatureSlowUAMem16 }, { } },
  { "i686", "Select the i686 processor", { X86::FeatureSlowUAMem16 }, { } },
  { "ivybridge", "Select the ivybridge processor", { X86::ProcIntelIVB, X86::FeatureSlowBTMem, X86::FeatureSlowUAMem32 }, { } },
  { "k6", "Select the k6 processor", { X86::FeatureSlowUAMem16, X86::FeatureMMX }, { } },
  { "k6-2", "Select the k6-2 processor", { X86::FeatureSlowUAMem16, X86::Feature3DNow }, { } },
  { "k6-3", "Select the k6-3 processor", { X86::FeatureSlowUAMem16, X86::Feature3DNow }, { } },
  { "k8", "Select the k8 processor", { X86::FeatureSlowUAMem16, X86::FeatureSSE2, X86::Feature3DNowA, X86::FeatureFXSR, X86::Feature64Bit, X86::FeatureSlowBTMem, X86::FeatureSlowSHLD }, { } },
  { "k8-sse3", "Select the k8-sse3 processor", { X86::FeatureSlowUAMem16, X86::FeatureSSE3, X86::Feature3DNowA, X86::FeatureFXSR, X86::FeatureCMPXCHG16B, X86::FeatureSlowBTMem, X86::FeatureSlowSHLD }, { } },
  { "knl", "Select the knl processor", { X86::ProcIntelIVB, X86::FeatureAVX512, X86::FeatureERI, X86::FeatureCDI, X86::FeaturePFI, X86::FeaturePREFETCHWT1, X86::FeatureADX, X86::FeatureRDSEED, X86::FeatureMOVBE, X86::FeatureLZCNT, X86::FeatureBMI, X86::FeatureBMI2, X86::FeatureFMA }, { } },
  { "nehalem", "Select the nehalem processor", { X86::FeatureMMX, X86::FeatureSSE42, X86::FeatureFXSR, X86::FeatureCMPXCHG16B, X86::FeatureSlowBTMem, X86::FeaturePOPCNT, X86::FeatureLAHFSAHF }, { } },
  { "nocona", "Select the nocona processor", { X86::FeatureSlowUAMem16, X86::FeatureMMX, X86::FeatureSSE3, X86::FeatureFXSR, X86::FeatureCMPXCHG16B, X86::FeatureSlowBTMem }, { } },
  { "opteron", "Select the opteron processor", { X86::FeatureSlowUAMem16, X86::FeatureSSE2, X86::Feature3DNowA, X86::FeatureFXSR, X86::Feature64Bit, X86::FeatureSlowBTMem, X86::FeatureSlowSHLD }, { } },
  { "opteron-sse3", "Select the opteron-sse3 processor", { X86::FeatureSlowUAMem16, X86::FeatureSSE3, X86::Feature3DNowA, X86::FeatureFXSR, X86::FeatureCMPXCHG16B, X86::FeatureSlowBTMem, X86::FeatureSlowSHLD }, { } },
  { "penryn", "Select the penryn processor", { X86::FeatureSlowUAMem16, X86::FeatureMMX, X86::FeatureSSE41, X86::FeatureFXSR, X86::FeatureCMPXCHG16B, X86::FeatureSlowBTMem, X86::FeatureLAHFSAHF }, { } },
  { "pentium", "Select the pentium processor", { X86::FeatureSlowUAMem16 }, { } },
  { "pentium-m", "Select the pentium-m processor", { X86::FeatureSlowUAMem16, X86::FeatureMMX, X86::FeatureSSE2, X86::FeatureFXSR, X86::FeatureSlowBTMem }, { } },
  { "pentium-mmx", "Select the pentium-mmx processor", { X86::FeatureSlowUAMem16, X86::FeatureMMX }, { } },
  { "pentium2", "Select the pentium2 processor", { X86::FeatureSlowUAMem16, X86::FeatureMMX, X86::FeatureCMOV, X86::FeatureFXSR }, { } },
  { "pentium3", "Select the pentium3 processor", { X86::FeatureSlowUAMem16, X86::FeatureMMX, X86::FeatureSSE1, X86::FeatureFXSR }, { } },
  { "pentium3m", "Select the pentium3m processor", { X86::FeatureSlowUAMem16, X86::FeatureMMX, X86::FeatureSSE1, X86::FeatureFXSR, X86::FeatureSlowBTMem }, { } },
  { "pentium4", "Select the pentium4 processor", { X86::FeatureSlowUAMem16, X86::FeatureMMX, X86::FeatureSSE2, X86::FeatureFXSR }, { } },
  { "pentium4m", "Select the pentium4m processor", { X86::FeatureSlowUAMem16, X86::FeatureMMX, X86::FeatureSSE2, X86::FeatureFXSR, X86::FeatureSlowBTMem }, { } },
  { "pentiumpro", "Select the pentiumpro processor", { X86::FeatureSlowUAMem16, X86::FeatureCMOV }, { } },
  { "prescott", "Select the prescott processor", { X86::FeatureSlowUAMem16, X86::FeatureMMX, X86::FeatureSSE3, X86::FeatureFXSR, X86::FeatureSlowBTMem }, { } },
  { "sandybridge", "Select the sandybridge processor", { X86::ProcIntelSNB, X86::FeatureSlowBTMem, X86::FeatureSlowUAMem32 }, { } },
  { "silvermont", "Select the silvermont processor", { X86::ProcIntelSLM, X86::FeatureMMX, X86::FeatureSSE42, X86::FeatureFXSR, X86::FeatureCMPXCHG16B, X86::FeatureMOVBE, X86::FeaturePOPCNT, X86::FeaturePCLMUL, X86::FeatureAES, X86::FeatureSlowDivide64, X86::FeatureCallRegIndirect, X86::FeaturePRFCHW, X86::FeatureSlowLEA, X86::FeatureSlowIncDec, X86::FeatureSlowBTMem, X86::FeatureLAHFSAHF }, { } },
  { "skl", "Select the skl processor", { X86::ProcIntelSKL }, { } },
  { "skx", "Select the skx processor", { X86::ProcIntelSKX }, { } },
  { "skylake", "Select the skylake processor", { X86::ProcIntelSKX }, { } },
  { "slm", "Select the slm processor", { X86::ProcIntelSLM, X86::FeatureMMX, X86::FeatureSSE42, X86::FeatureFXSR, X86::FeatureCMPXCHG16B, X86::FeatureMOVBE, X86::FeaturePOPCNT, X86::FeaturePCLMUL, X86::FeatureAES, X86::FeatureSlowDivide64, X86::FeatureCallRegIndirect, X86::FeaturePRFCHW, X86::FeatureSlowLEA, X86::FeatureSlowIncDec, X86::FeatureSlowBTMem, X86::FeatureLAHFSAHF }, { } },
  { "westmere", "Select the westmere processor", { X86::FeatureMMX, X86::FeatureSSE42, X86::FeatureFXSR, X86::FeatureCMPXCHG16B, X86::FeatureSlowBTMem, X86::FeaturePOPCNT, X86::FeatureAES, X86::FeaturePCLMUL, X86::FeatureLAHFSAHF }, { } },
  { "winchip-c6", "Select the winchip-c6 processor", { X86::FeatureSlowUAMem16, X86::FeatureMMX }, { } },
  { "winchip2", "Select the winchip2 processor", { X86::FeatureSlowUAMem16, X86::Feature3DNow }, { } },
  { "x86-64", "Select the x86-64 processor", { X86::FeatureMMX, X86::FeatureSSE2, X86::FeatureFXSR, X86::Feature64Bit, X86::FeatureSlowBTMem }, { } },
  { "yonah", "Select the yonah processor", { X86::FeatureSlowUAMem16, X86::FeatureMMX, X86::FeatureSSE3, X86::FeatureFXSR, X86::FeatureSlowBTMem }, { } }
};

#ifdef DBGFIELD
#error "<target>GenSubtargetInfo.inc requires a DBGFIELD macro"
#endif
#ifndef NDEBUG
#define DBGFIELD(x) x,
#else
#define DBGFIELD(x)
#endif

#undef DBGFIELD
static inline MCSubtargetInfo *createX86MCSubtargetInfoImpl(const Triple &TT, StringRef CPU, StringRef FS) {
  return new MCSubtargetInfo(TT, CPU, FS, X86FeatureKV, X86SubTypeKV, NULL);
}

} // end llvm namespace
#endif // GET_SUBTARGETINFO_MC_DESC


#ifdef GET_SUBTARGETINFO_TARGET_DESC
#undef GET_SUBTARGETINFO_TARGET_DESC
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
// ParseSubtargetFeatures - Parses features string setting specified
// subtarget options.
void llvm_ks::X86Subtarget::ParseSubtargetFeatures(StringRef CPU, StringRef FS) {
  DEBUG(dbgs() << "\nFeatures:" << FS);
  DEBUG(dbgs() << "\nCPU:" << CPU << "\n\n");
  InitMCProcessorInfo(CPU, FS);
  const FeatureBitset& Bits = getFeatureBits();
  if (Bits[X86::Feature3DNow] && X863DNowLevel < ThreeDNow) X863DNowLevel = ThreeDNow;
  if (Bits[X86::Feature3DNowA] && X863DNowLevel < ThreeDNowA) X863DNowLevel = ThreeDNowA;
  if (Bits[X86::Feature64Bit]) HasX86_64 = true;
  if (Bits[X86::FeatureADX]) HasADX = true;
  if (Bits[X86::FeatureAES]) HasAES = true;
  if (Bits[X86::FeatureAVX] && X86SSELevel < AVX) X86SSELevel = AVX;
  if (Bits[X86::FeatureAVX2] && X86SSELevel < AVX2) X86SSELevel = AVX2;
  if (Bits[X86::FeatureAVX512] && X86SSELevel < AVX512F) X86SSELevel = AVX512F;
  if (Bits[X86::FeatureBMI]) HasBMI = true;
  if (Bits[X86::FeatureBMI2]) HasBMI2 = true;
  if (Bits[X86::FeatureBWI]) HasBWI = true;
  if (Bits[X86::FeatureCDI]) HasCDI = true;
  if (Bits[X86::FeatureCLFLUSHOPT]) HasCLFLUSHOPT = true;
  if (Bits[X86::FeatureCLWB]) HasCLWB = true;
  if (Bits[X86::FeatureCMOV]) HasCMov = true;
  if (Bits[X86::FeatureCMPXCHG16B]) HasCmpxchg16b = true;
  if (Bits[X86::FeatureCallRegIndirect]) CallRegIndirect = true;
  if (Bits[X86::FeatureDQI]) HasDQI = true;
  if (Bits[X86::FeatureERI]) HasERI = true;
  if (Bits[X86::FeatureF16C]) HasF16C = true;
  if (Bits[X86::FeatureFMA]) HasFMA = true;
  if (Bits[X86::FeatureFMA4]) HasFMA4 = true;
  if (Bits[X86::FeatureFSGSBase]) HasFSGSBase = true;
  if (Bits[X86::FeatureFXSR]) HasFXSR = true;
  if (Bits[X86::FeatureHLE]) HasHLE = true;
  if (Bits[X86::FeatureIFMA]) HasIFMA = true;
  if (Bits[X86::FeatureINVPCID]) HasInvPCId = true;
  if (Bits[X86::FeatureLAHFSAHF]) HasLAHFSAHF = true;
  if (Bits[X86::FeatureLEAForSP]) UseLeaForSP = true;
  if (Bits[X86::FeatureLEAUsesAG]) LEAUsesAG = true;
  if (Bits[X86::FeatureLZCNT]) HasLZCNT = true;
  if (Bits[X86::FeatureMMX] && X863DNowLevel < MMX) X863DNowLevel = MMX;
  if (Bits[X86::FeatureMOVBE]) HasMOVBE = true;
  if (Bits[X86::FeatureMPX]) HasMPX = true;
  if (Bits[X86::FeaturePCLMUL]) HasPCLMUL = true;
  if (Bits[X86::FeaturePCOMMIT]) HasPCOMMIT = true;
  if (Bits[X86::FeaturePFI]) HasPFI = true;
  if (Bits[X86::FeaturePKU]) HasPKU = true;
  if (Bits[X86::FeaturePOPCNT]) HasPOPCNT = true;
  if (Bits[X86::FeaturePREFETCHWT1]) HasPFPREFETCHWT1 = true;
  if (Bits[X86::FeaturePRFCHW]) HasPRFCHW = true;
  if (Bits[X86::FeaturePadShortFunctions]) PadShortFunctions = true;
  if (Bits[X86::FeatureRDRAND]) HasRDRAND = true;
  if (Bits[X86::FeatureRDSEED]) HasRDSEED = true;
  if (Bits[X86::FeatureRTM]) HasRTM = true;
  if (Bits[X86::FeatureSGX]) HasSGX = true;
  if (Bits[X86::FeatureSHA]) HasSHA = true;
  if (Bits[X86::FeatureSMAP]) HasSMAP = true;
  if (Bits[X86::FeatureSSE1] && X86SSELevel < SSE1) X86SSELevel = SSE1;
  if (Bits[X86::FeatureSSE2] && X86SSELevel < SSE2) X86SSELevel = SSE2;
  if (Bits[X86::FeatureSSE3] && X86SSELevel < SSE3) X86SSELevel = SSE3;
  if (Bits[X86::FeatureSSE4A]) HasSSE4A = true;
  if (Bits[X86::FeatureSSE41] && X86SSELevel < SSE41) X86SSELevel = SSE41;
  if (Bits[X86::FeatureSSE42] && X86SSELevel < SSE42) X86SSELevel = SSE42;
  if (Bits[X86::FeatureSSEUnalignedMem]) HasSSEUnalignedMem = true;
  if (Bits[X86::FeatureSSSE3] && X86SSELevel < SSSE3) X86SSELevel = SSSE3;
  if (Bits[X86::FeatureSlowBTMem]) IsBTMemSlow = true;
  if (Bits[X86::FeatureSlowDivide32]) HasSlowDivide32 = true;
  if (Bits[X86::FeatureSlowDivide64]) HasSlowDivide64 = true;
  if (Bits[X86::FeatureSlowIncDec]) SlowIncDec = true;
  if (Bits[X86::FeatureSlowLEA]) SlowLEA = true;
  if (Bits[X86::FeatureSlowSHLD]) IsSHLDSlow = true;
  if (Bits[X86::FeatureSlowUAMem16]) IsUAMem16Slow = true;
  if (Bits[X86::FeatureSlowUAMem32]) IsUAMem32Slow = true;
  if (Bits[X86::FeatureSoftFloat]) UseSoftFloat = true;
  if (Bits[X86::FeatureTBM]) HasTBM = true;
  if (Bits[X86::FeatureVBMI]) HasVBMI = true;
  if (Bits[X86::FeatureVLX]) HasVLX = true;
  if (Bits[X86::FeatureVMFUNC]) HasVMFUNC = true;
  if (Bits[X86::FeatureXOP]) HasXOP = true;
  if (Bits[X86::FeatureXSAVE]) HasXSAVE = true;
  if (Bits[X86::FeatureXSAVEC]) HasXSAVEC = true;
  if (Bits[X86::FeatureXSAVEOPT]) HasXSAVEOPT = true;
  if (Bits[X86::FeatureXSAVES]) HasXSAVES = true;
  if (Bits[X86::Mode16Bit]) In16BitMode = true;
  if (Bits[X86::Mode32Bit]) In32BitMode = true;
  if (Bits[X86::Mode64Bit]) In64BitMode = true;
  if (Bits[X86::ProcIntelAtom] && X86ProcFamily < IntelAtom) X86ProcFamily = IntelAtom;
  if (Bits[X86::ProcIntelBDW] && X86ProcFamily < IntelBDW) X86ProcFamily = IntelBDW;
  if (Bits[X86::ProcIntelCNL] && X86ProcFamily < IntelCNL) X86ProcFamily = IntelCNL;
  if (Bits[X86::ProcIntelHSW] && X86ProcFamily < IntelHSW) X86ProcFamily = IntelHSW;
  if (Bits[X86::ProcIntelIVB] && X86ProcFamily < IntelIVB) X86ProcFamily = IntelIVB;
  if (Bits[X86::ProcIntelSKL] && X86ProcFamily < IntelSKL) X86ProcFamily = IntelSKL;
  if (Bits[X86::ProcIntelSKX] && X86ProcFamily < IntelSKX) X86ProcFamily = IntelSKX;
  if (Bits[X86::ProcIntelSLM] && X86ProcFamily < IntelSLM) X86ProcFamily = IntelSLM;
  if (Bits[X86::ProcIntelSNB] && X86ProcFamily < IntelSNB) X86ProcFamily = IntelSNB;
}
#endif // GET_SUBTARGETINFO_TARGET_DESC
