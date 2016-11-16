#!/usr/bin/python

# Test BL <target> instruction for ARM32

# Github issue: #257
# Author: shakamd

from keystone import *

import regress

class TestARM(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
        # Assemble to get back insn encoding & statement count
        encoding, count = ks.asm(b"""
                    push {r4, r5, r6, r7, r8, sb, sl, lr}
                    mov r4, r0
                    mov r0, r1
                    mov r6, r1
                    and sb, r2, #0xff
                    lsr r7, r2, #8
                    bl #0xfffe5078
                    """)
        # Assert the result
        self.assertEqual(encoding[:4], [ 0x16, 0x94, 0xff, 0xeb ])

if __name__ == '__main__':
    regress.main()
