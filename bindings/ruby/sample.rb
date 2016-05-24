#!/usr/bin/env ruby

# Sample code for Keystone assembler engine.
# By Sascha Schirra <sashs82@gmail.com>, 2016

require 'keystone'

include Keystone

def test_ks(arch, mode, code, syntax=0)
    ks = Ks.new(arch, mode)
    if syntax != 0
        ks.syntax = syntax
    end
    encoding, count = ks.asm(code)

    print("%s = [ " % code)
    encoding.each_char do |i|
        print("%02x " % i.ord)
    end
    puts("]")
end


# X86
test_ks(KS_ARCH_X86, KS_MODE_16, "add eax, ecx")
test_ks(KS_ARCH_X86, KS_MODE_32, "add eax, ecx")
test_ks(KS_ARCH_X86, KS_MODE_64, "add rax, rcx")
test_ks(KS_ARCH_X86, KS_MODE_32, "add %ecx, %eax", KS_OPT_SYNTAX_ATT)
test_ks(KS_ARCH_X86, KS_MODE_64, "add %rcx, %rax", KS_OPT_SYNTAX_ATT)

# ARM
test_ks(KS_ARCH_ARM, KS_MODE_ARM, "sub r1, r2, r5")
test_ks(KS_ARCH_ARM, KS_MODE_ARM + KS_MODE_BIG_ENDIAN, "sub r1, r2, r5")
test_ks(KS_ARCH_ARM, KS_MODE_THUMB, "movs r4, #0xf0")
test_ks(KS_ARCH_ARM, KS_MODE_THUMB + KS_MODE_BIG_ENDIAN, "movs r4, #0xf0")

# ARM64
test_ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, "ldr w1, [sp, #0x8]")

# Hexagon
test_ks(KS_ARCH_HEXAGON, KS_MODE_BIG_ENDIAN, "v23.w=vavg(v11.w,v2.w):rnd")

# Mips
test_ks(KS_ARCH_MIPS, KS_MODE_MIPS32, "and $9, $6, $7")
test_ks(KS_ARCH_MIPS, KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN, "and $9, $6, $7")
test_ks(KS_ARCH_MIPS, KS_MODE_MIPS64, "and $9, $6, $7")
test_ks(KS_ARCH_MIPS, KS_MODE_MIPS64 + KS_MODE_BIG_ENDIAN, "and $9, $6, $7")

# PowerPC
test_ks(KS_ARCH_PPC, KS_MODE_PPC32 + KS_MODE_BIG_ENDIAN, "add 1, 2, 3")
test_ks(KS_ARCH_PPC, KS_MODE_PPC64, "add 1, 2, 3")
test_ks(KS_ARCH_PPC, KS_MODE_PPC64 + KS_MODE_BIG_ENDIAN, "add 1, 2, 3")

# Sparc
test_ks(KS_ARCH_SPARC, KS_MODE_SPARC32 + KS_MODE_LITTLE_ENDIAN, "add %g1, %g2, %g3")
test_ks(KS_ARCH_SPARC, KS_MODE_SPARC32 + KS_MODE_BIG_ENDIAN, "add %g1, %g2, %g3")

# SystemZ
test_ks(KS_ARCH_SYSTEMZ, KS_MODE_BIG_ENDIAN, "a %r0, 4095(%r15,%r1)")
