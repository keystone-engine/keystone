#!/usr/bin/python

# Test int3 instruction

# Github issue: #7
# Author: Nguyen Anh Quynh

from keystone import *

import regress

class TestX86(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        # Assemble to get back insn encoding & statement count
        encoding, count = ks.asm(b"int 3")
        # Assert the result
        self.assertEqual(encoding, [ 0xcd, 0x03 ])

if __name__ == '__main__':
    regress.main()
