#/bin/sh
# generates all fuzz targets for different architectures from the template in fuzz_asm_x86_32.c

sed 's/KS_MODE_32/KS_MODE_64/' fuzz_asm_x86_32.c > fuzz_asm_x86_64.c
sed 's/KS_MODE_32/KS_MODE_16/' fuzz_asm_x86_32.c > fuzz_asm_x86_16.c

sed 's/KS_ARCH_X86/KS_ARCH_ARM/' fuzz_asm_x86_32.c | sed 's/KS_MODE_32/KS_MODE_ARM+KS_MODE_LITTLE_ENDIAN/' > fuzz_asm_arm_arm.c
sed 's/KS_ARCH_X86/KS_ARCH_ARM/' fuzz_asm_x86_32.c | sed 's/KS_MODE_32/KS_MODE_ARM+KS_MODE_BIG_ENDIAN/' > fuzz_asm_arm_armbe.c
sed 's/KS_ARCH_X86/KS_ARCH_ARM/' fuzz_asm_x86_32.c | sed 's/KS_MODE_32/KS_MODE_THUMB+KS_MODE_LITTLE_ENDIAN/' > fuzz_asm_arm_thumb.c
sed 's/KS_ARCH_X86/KS_ARCH_ARM/' fuzz_asm_x86_32.c | sed 's/KS_MODE_32/KS_MODE_THUMB+KS_MODE_BIG_ENDIAN/' > fuzz_asm_arm_thumbbe.c
sed 's/KS_ARCH_X86/KS_ARCH_ARM/' fuzz_asm_x86_32.c | sed 's/KS_MODE_32/KS_MODE_ARM+KS_MODE_LITTLE_ENDIAN+KS_MODE_V8/' > fuzz_asm_armv8_arm.c
sed 's/KS_ARCH_X86/KS_ARCH_ARM/' fuzz_asm_x86_32.c | sed 's/KS_MODE_32/KS_MODE_ARM+KS_MODE_BIG_ENDIAN+KS_MODE_V8/' > fuzz_asm_arm_armv8be.c
sed 's/KS_ARCH_X86/KS_ARCH_ARM/' fuzz_asm_x86_32.c | sed 's/KS_MODE_32/KS_MODE_THUMB+KS_MODE_LITTLE_ENDIAN+KS_MODE_V8/' > fuzz_asm_arm_thumbv8.c
sed 's/KS_ARCH_X86/KS_ARCH_ARM/' fuzz_asm_x86_32.c | sed 's/KS_MODE_32/KS_MODE_THUMB+KS_MODE_BIG_ENDIAN+KS_MODE_V8/' > fuzz_asm_arm_thumbv8be.c

sed 's/KS_ARCH_X86/KS_ARCH_ARM64/' fuzz_asm_x86_32.c | sed 's/KS_MODE_32/KS_MODE_LITTLE_ENDIAN/' > fuzz_asm_arm64_arm.c

sed 's/KS_ARCH_X86/KS_ARCH_HEXAGON/' fuzz_asm_x86_32.c | sed 's/KS_MODE_32/KS_MODE_BIG_ENDIAN/' > fuzz_asm_hex.c

sed 's/KS_ARCH_X86/KS_ARCH_MIPS/' fuzz_asm_x86_32.c | sed 's/KS_MODE_32/KS_MODE_MIPS32+KS_MODE_LITTLE_ENDIAN/' > fuzz_asm_mips.c
sed 's/KS_ARCH_X86/KS_ARCH_MIPS/' fuzz_asm_x86_32.c | sed 's/KS_MODE_32/KS_MODE_MIPS32+KS_MODE_BIG_ENDIAN/' > fuzz_asm_mipsbe.c
sed 's/KS_ARCH_X86/KS_ARCH_MIPS/' fuzz_asm_x86_32.c | sed 's/KS_MODE_32/KS_MODE_MIPS64+KS_MODE_LITTLE_ENDIAN/' > fuzz_asm_mips64.c
sed 's/KS_ARCH_X86/KS_ARCH_MIPS/' fuzz_asm_x86_32.c | sed 's/KS_MODE_32/KS_MODE_MIPS64+KS_MODE_BIG_ENDIAN/' > fuzz_asm_mips64be.c

sed 's/KS_ARCH_X86/KS_ARCH_PPC/' fuzz_asm_x86_32.c | sed 's/KS_MODE_32/KS_MODE_PPC32+KS_MODE_BIG_ENDIAN/' > fuzz_asm_ppc32be.c
sed 's/KS_ARCH_X86/KS_ARCH_PPC/' fuzz_asm_x86_32.c | sed 's/KS_MODE_32/KS_MODE_PPC64+KS_MODE_LITTLE_ENDIAN/' > fuzz_asm_ppc64.c
sed 's/KS_ARCH_X86/KS_ARCH_PPC/' fuzz_asm_x86_32.c | sed 's/KS_MODE_32/KS_MODE_PPC64+KS_MODE_BIG_ENDIAN/' > fuzz_asm_ppc64be.c


sed 's/KS_ARCH_X86/KS_ARCH_SPARC/' fuzz_asm_x86_32.c | sed 's/KS_MODE_32/KS_MODE_SPARC32+KS_MODE_LITTLE_ENDIAN/' > fuzz_asm_sparc.c
sed 's/KS_ARCH_X86/KS_ARCH_SPARC/' fuzz_asm_x86_32.c | sed 's/KS_MODE_32/KS_MODE_SPARC32+KS_MODE_BIG_ENDIAN/' > fuzz_asm_sparcbe.c
sed 's/KS_ARCH_X86/KS_ARCH_SPARC/' fuzz_asm_x86_32.c | sed 's/KS_MODE_32/KS_MODE_SPARC64+KS_MODE_BIG_ENDIAN/' > fuzz_asm_sparc64be.c

sed 's/KS_ARCH_X86/KS_ARCH_SYSTEMZ/' fuzz_asm_x86_32.c | sed 's/KS_MODE_32/KS_MODE_BIG_ENDIAN/' > fuzz_asm_systemz.c

sed 's/KS_ARCH_X86/KS_ARCH_EVM/' fuzz_asm_x86_32.c | sed 's/KS_MODE_32/0/' > fuzz_asm_evm.c
