namespace KeystoneNET
{
    public enum KeystoneArchitecture : int
    {
        KS_ARCH_ARM = 1,    // ARM architecture (including Thumb, Thumb-2)
        KS_ARCH_ARM64,      // ARM-64, also called AArch64
        KS_ARCH_MIPS,       // Mips architecture
        KS_ARCH_X86,        // X86 architecture (including x86 & x86-64)
        KS_ARCH_PPC,        // PowerPC architecture (currently unsupported)
        KS_ARCH_SPARC,      // Sparc architecture
        KS_ARCH_SYSTEMZ,    // SystemZ architecture (S390X)
        KS_ARCH_HEXAGON,    // Hexagon architecture
        KS_ARCH_MAX,
    };
}
