#!/usr/bin/python

# Test if addr == 0 and addr != 0 produces the same results on a NOP.

# Github issue: #9
# Author: Duncan (mrexodia)

from keystone import *

import regress

class TestX86Intel(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        # Assemble with zero addr
        encoding1, count1 = ks.asm("nop", 0)
        # Assemble with non-zero addr
        encoding2, count2 = ks.asm("nop", 0x9123FFE1)
        # Assert the result
        self.assertEqual(encoding1, [ 0x90 ])
        self.assertEqual(count1, 1)
        self.assertEqual(encoding1, encoding2)
        self.assertEqual(count1, count2)

if __name__ == '__main__':
    regress.main()
