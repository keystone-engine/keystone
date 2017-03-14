namespace KeystoneNET
{
    public enum KeystoneMode : uint
    {
        KS_MODE_LITTLE_ENDIAN = 0,    // little-endian mode (default mode)
        KS_MODE_BIG_ENDIAN = 1 << 30, // big-endian mode
                                      // arm / arm64
        KS_MODE_ARM = 1 << 0,              // ARM mode
        KS_MODE_THUMB = 1 << 4,       // THUMB mode (including Thumb-2)
        KS_MODE_V8 = 1 << 6,          // ARMv8 A32 encodings for ARM
                                      // mips
        KS_MODE_MICRO = 1 << 4,       // MicroMips mode
        KS_MODE_MIPS3 = 1 << 5,       // Mips III ISA
        KS_MODE_MIPS32R6 = 1 << 6,    // Mips32r6 ISA
        KS_MODE_MIPS32 = 1 << 2,      // Mips32 ISA
        KS_MODE_MIPS64 = 1 << 3,      // Mips64 ISA
                                      // x86 / x64
        KS_MODE_16 = 1 << 1,          // 16-bit mode
        KS_MODE_32 = 1 << 2,          // 32-bit mode
        KS_MODE_64 = 1 << 3,          // 64-bit mode
                                      // ppc 
        KS_MODE_PPC32 = 1 << 2,       // 32-bit mode
        KS_MODE_PPC64 = 1 << 3,       // 64-bit mode
        KS_MODE_QPX = 1 << 4,         // Quad Processing eXtensions mode
                                      // sparc
        KS_MODE_SPARC32 = 1 << 2,     // 32-bit mode
        KS_MODE_SPARC64 = 1 << 3,     // 64-bit mode
        KS_MODE_V9 = 1 << 4,          // SparcV9 mode
    };
}
