#!/usr/bin/python

# Test BLX <label> instruction for THUMB

# Github issue: #248
# Author: dmxcsnsbh

from keystone import *

import regress

class TestARM(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
        # Assemble to get back insn encoding & statement count
        encoding, count = ks.asm(b"""
                    blx  func
                    movs r0, #0
                    movs r1, #1
                func:
                    """)
        # Assert the result
        # self.assertEqual(encoding, [ 0x00, 0xf0, 0x02, 0xe8, 0x00, 0x20, 0x01, 0x21  ])
        self.assertEqual(encoding[:4], [ 0x00, 0xf0, 0x02, 0xe8 ])

if __name__ == '__main__':
    regress.main()
