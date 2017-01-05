#!/usr/bin/python

# Test JAL <plain address> instruction for MIPS64

# Github issue: #269
# Author: LdyEax

from keystone import *

import regress

class TestMIPS(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_MIPS, KS_MODE_MIPS64 + KS_MODE_BIG_ENDIAN)
        # Assemble to get back insn encoding & statement count
        encoding, count = ks.asm(b"jal 0")
        # Assert the result
        self.assertEqual(encoding[:4], [ 0x0C, 0x00, 0x00, 0x00 ])

if __name__ == '__main__':
    regress.main()
