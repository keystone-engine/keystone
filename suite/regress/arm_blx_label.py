#!/usr/bin/python

# Test BLX <label> instruction for ARM32

# Github issue: #248
# Author: dmxcsnsbh

from keystone import *

import regress

class TestARM(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
        # Assemble to get back insn encoding & statement count
        encoding, count = ks.asm(b"""
                    blx func
                    sub r0, r0, r0
                    sub r1, r1, r1
                func:
                    """)
        # Assert the result
        # self.assertEqual(encoding, [ 0x01, 0x00, 0x00, 0xfa, 0x00, 0x00, 0x40, 0xe0, 0x01, 0x10, 0x41, 0xe0 ])
        self.assertEqual(encoding[:4], [ 0x01, 0x00, 0x00, 0xfa ])

if __name__ == '__main__':
    regress.main()
