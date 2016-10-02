#!/usr/bin/env python

# Sample code for Keystone assembler engine.
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2016

from __future__ import print_function
from keystone import *


def test_ks(arch, mode, code, syntax=0):
    ks = Ks(arch, mode)
    if syntax != 0:
        ks.syntax = syntax

    encoding, count = ks.asm(code)

    print("%s = [ " % code, end='')
    for i in encoding:
        print("%02x " % i, end='')
    print("]")


# test symbol resolver
def test_sym_resolver():
    def sym_resolver(symbol, value):
        # is this the missing symbol we want to handle?
        if symbol == "_l1":
            # put value of this symbol in @value
            value = 0x1002
            # we handled this symbol, so return true
            return True

        # we did not handle this symbol, so return false
        return False

    ks = Ks(KS_ARCH_X86, KS_MODE_32)

    # register callback for symbol resolver
    ks.sym_resolver = sym_resolver

    CODE = b"jmp _l1; nop; _l1:"
    encoding, count = ks.asm(CODE, 0x1000)

    print("%s = [ " % CODE, end='')
    for i in encoding:
        print("%02x " % i, end='')
    print("]")


if __name__ == '__main__':
    # X86
    test_ks(KS_ARCH_X86, KS_MODE_16, b"add eax, ecx")
    test_ks(KS_ARCH_X86, KS_MODE_32, b"add eax, ecx")
    test_ks(KS_ARCH_X86, KS_MODE_64, b"add rax, rcx")
    test_ks(KS_ARCH_X86, KS_MODE_32, b"add %ecx, %eax", KS_OPT_SYNTAX_ATT)
    test_ks(KS_ARCH_X86, KS_MODE_64, b"add %rcx, %rax", KS_OPT_SYNTAX_ATT)

    test_ks(KS_ARCH_X86, KS_MODE_32, b"add eax, 0x15")
    test_ks(KS_ARCH_X86, KS_MODE_32, b"add eax, 15h");
    test_ks(KS_ARCH_X86, KS_MODE_32, b"add eax, 15")

    # RADIX16 syntax Intel (default syntax)
    test_ks(KS_ARCH_X86, KS_MODE_32, b"add eax, 15", KS_OPT_SYNTAX_RADIX16)
    # RADIX16 syntax for AT&T
    test_ks(KS_ARCH_X86, KS_MODE_32, b"add $15, %eax", KS_OPT_SYNTAX_RADIX16 | KS_OPT_SYNTAX_ATT)

    # ARM
    test_ks(KS_ARCH_ARM, KS_MODE_ARM, b"sub r1, r2, r5")
    test_ks(KS_ARCH_ARM, KS_MODE_ARM + KS_MODE_BIG_ENDIAN, b"sub r1, r2, r5")
    test_ks(KS_ARCH_ARM, KS_MODE_THUMB, b"movs r4, #0xf0")
    test_ks(KS_ARCH_ARM, KS_MODE_THUMB + KS_MODE_BIG_ENDIAN, b"movs r4, #0xf0")

    # ARM64
    test_ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, b"ldr w1, [sp, #0x8]")

    # Hexagon
    test_ks(KS_ARCH_HEXAGON, KS_MODE_BIG_ENDIAN, b"v23.w=vavg(v11.w,v2.w):rnd")

    # Mips
    test_ks(KS_ARCH_MIPS, KS_MODE_MIPS32, b"and $9, $6, $7")
    test_ks(KS_ARCH_MIPS, KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN, b"and $9, $6, $7")
    test_ks(KS_ARCH_MIPS, KS_MODE_MIPS64, b"and $9, $6, $7")
    test_ks(KS_ARCH_MIPS, KS_MODE_MIPS64 + KS_MODE_BIG_ENDIAN, b"and $9, $6, $7")

    # PowerPC
    test_ks(KS_ARCH_PPC, KS_MODE_PPC32 + KS_MODE_BIG_ENDIAN, b"add 1, 2, 3")
    test_ks(KS_ARCH_PPC, KS_MODE_PPC64, b"add 1, 2, 3")
    test_ks(KS_ARCH_PPC, KS_MODE_PPC64 + KS_MODE_BIG_ENDIAN, b"add 1, 2, 3")

    # Sparc
    test_ks(KS_ARCH_SPARC, KS_MODE_SPARC32 + KS_MODE_LITTLE_ENDIAN, b"add %g1, %g2, %g3")
    test_ks(KS_ARCH_SPARC, KS_MODE_SPARC32 + KS_MODE_BIG_ENDIAN, b"add %g1, %g2, %g3")

    # SystemZ
    test_ks(KS_ARCH_SYSTEMZ, KS_MODE_BIG_ENDIAN, b"a %r0, 4095(%r15,%r1)")

    # test symbol resolver
    test_sym_resolver()
