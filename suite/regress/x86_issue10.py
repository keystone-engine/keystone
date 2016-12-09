#!/usr/bin/python

# Test 'push word 0xd'

# Github issue: #10
# Author: Duncan (mrexodia)

from keystone import *

import regress

class TestX86(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        # Assemble to get back insn encoding & statement count
        encoding1, _ = ks.asm(b"push 0xd")
        encoding2, _ = ks.asm(b"push word 0xd")
        encoding3, _ = ks.asm(b"push word 0x1234")
        # Assert the result
        self.assertEqual(encoding1, [ 0x6a, 0x0d ])
        self.assertEqual(encoding2, [ 0x66, 0x6a, 0x0d ])
        self.assertEqual(encoding3, [ 0x66, 0x68, 0x34, 0x12 ])

if __name__ == '__main__':
    regress.main()
