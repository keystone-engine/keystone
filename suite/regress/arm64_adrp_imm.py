#!/usr/bin/python
# KhiemNNM, 2016

# This tests the ADRP Xd, #imm.

# Github issue: #259
# Author: Khiem Nguyen

from keystone import *

import regress

class TestARM(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_ARM64, 0)
        # Assemble to get back insn encoding & statement count
        encoding, count = ks.asm(b"ADRP X8,#0x10274400",0x100011C38)
        # Assert the result
        self.assertEqual(encoding, [ 0x88 ,0x39, 0x01 ,0xF0 ])

if __name__ == '__main__':
    regress.main()
