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
                    nop
                    bl #0xfffe5064
                    """)
        # Assert the result
        self.assertEqual(encoding[-4:], [ 0x16, 0x94, 0xff, 0xeb ])

        encoding, count = ks.asm(b"""
                    nop
                    nop
                    bl #0xfffe5068
                    """)
        # Assert the result
        self.assertEqual(encoding[-4:], [ 0x16, 0x94, 0xff, 0xeb ])

        encoding, count = ks.asm(b"""
                    nop
                    lsr r7, r2, #8
                    bl #0xfffe5068
                    """)
        # Assert the result
        self.assertEqual(encoding[-4:], [ 0x16, 0x94, 0xff, 0xeb ])

if __name__ == '__main__':
    regress.main()
