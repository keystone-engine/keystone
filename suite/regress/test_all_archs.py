#!/usr/bin/python

# Test all architectures

# Github issue: #xxx
# Author: Nguyen Anh Quynh

from __future__ import print_function
from keystone import *

import regress


class TestAll(regress.RegressTest):
    def kstest(self, arch, mode, code, expect, syntax = 0):
        ks = Ks(arch, mode)
        if syntax != 0:
            ks.syntax = syntax
        encoding, count = ks.asm(code)
        #print("%s = [ " % code, end='')
        #for i in encoding:
        #    print("0x%02x, " % i, end='')
        #print("]")
        self.assertEqual(encoding, expect)

    def runTest(self):
        # X86
        self.kstest(KS_ARCH_X86, KS_MODE_16, b"add eax, ecx", [ 0x66, 0x01, 0xc8 ])
        self.kstest(KS_ARCH_X86, KS_MODE_32, b"add eax, ecx", [ 0x01, 0xc8 ])
        self.kstest(KS_ARCH_X86, KS_MODE_64, b"add rax, rcx", [ 0x48, 0x01, 0xc8 ])
        self.kstest(KS_ARCH_X86, KS_MODE_32, b"add %ecx, %eax", [ 0x01, 0xc8 ], KS_OPT_SYNTAX_ATT)
        self.kstest(KS_ARCH_X86, KS_MODE_64, b"add %rcx, %rax", [ 0x48, 0x01, 0xc8 ], KS_OPT_SYNTAX_ATT)

        # ARM
        self.kstest(KS_ARCH_ARM, KS_MODE_ARM, b"sub r1, r2, r5", [ 0x05, 0x10, 0x42, 0xe0 ])
        self.kstest(KS_ARCH_ARM, KS_MODE_ARM + KS_MODE_BIG_ENDIAN, b"sub r1, r2, r5", [ 0xe0, 0x42, 0x10, 0x05 ])
        self.kstest(KS_ARCH_ARM, KS_MODE_THUMB, b"movs r4, #0xf0", [ 0xf0, 0x24 ])
        self.kstest(KS_ARCH_ARM, KS_MODE_THUMB + KS_MODE_BIG_ENDIAN, b"movs r4, #0xf0", [ 0x24, 0xf0 ])

        # ARM64
        self.kstest(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, b"ldr w1, [sp, #0x8]", [ 0xe1, 0x0b, 0x40, 0xb9 ])

        # Hexagon
        self.kstest(KS_ARCH_HEXAGON, KS_MODE_BIG_ENDIAN, b"v23.w=vavg(v11.w,v2.w):rnd", [ 0xd7, 0xcb, 0xe2, 0x1c ])

        # Mips
        self.kstest(KS_ARCH_MIPS, KS_MODE_MIPS32, b"and $9, $6, $7", [ 0x24, 0x48, 0xc7, 0x00 ])
        self.kstest(KS_ARCH_MIPS, KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN, b"and $9, $6, $7", [ 0x00, 0xc7, 0x48, 0x24 ])
        self.kstest(KS_ARCH_MIPS, KS_MODE_MIPS64, b"and $9, $6, $7", [ 0x24, 0x48, 0xc7, 0x00 ])
        self.kstest(KS_ARCH_MIPS, KS_MODE_MIPS64 + KS_MODE_BIG_ENDIAN, b"and $9, $6, $7", [ 0x00, 0xc7, 0x48, 0x24 ])

        # PowerPC
        self.kstest(KS_ARCH_PPC, KS_MODE_PPC32 + KS_MODE_BIG_ENDIAN, b"add 1, 2, 3", [ 0x7c, 0x22, 0x1a, 0x14 ])
        self.kstest(KS_ARCH_PPC, KS_MODE_PPC64, b"add 1, 2, 3", [ 0x14, 0x1a, 0x22, 0x7c ])
        self.kstest(KS_ARCH_PPC, KS_MODE_PPC64 + KS_MODE_BIG_ENDIAN, b"add 1, 2, 3", [ 0x7c, 0x22, 0x1a, 0x14 ])

        # Sparc
        self.kstest(KS_ARCH_SPARC, KS_MODE_SPARC32 + KS_MODE_LITTLE_ENDIAN, b"add %g1, %g2, %g3", [ 0x02, 0x40, 0x00, 0x86 ])
        self.kstest(KS_ARCH_SPARC, KS_MODE_SPARC32 + KS_MODE_BIG_ENDIAN, b"add %g1, %g2, %g3", [ 0x86, 0x00, 0x40, 0x02 ])

        # SystemZ
        self.kstest(KS_ARCH_SYSTEMZ, KS_MODE_BIG_ENDIAN, b"a %r0, 4095(%r15,%r1)", [ 0x5a, 0x0f, 0x1f, 0xff ])


if __name__ == '__main__':
    regress.main()
