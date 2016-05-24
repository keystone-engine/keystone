#!/usr/bin/python

# Tests if the SS segment override prefix is not explicitly produced when unnecessary

# Github issue: #9
# Author: Duncan (mrexodia)

from keystone import *

import regress

class TestX86(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        # Assemble to get back insn encoding & statement count
        encoding1, _ = ks.asm(b"MOV EAX,DWORD PTR SS:[ESP+8]")
        encoding2, _ = ks.asm(b"MOV EAX,DWORD PTR SS:[EBP+8]")
        # Assert the result
        self.assertEqual(encoding1, [ 0x8B, 0x44, 0x24, 0x08 ])
        self.assertEqual(encoding2, [ 0x8B, 0x45, 0x08 ])

        encoding, _ = ks.asm(b"MOV DWORD PTR SS:[EBP-0xC],0x1994000")
        self.assertEqual(encoding, [ 0xC7, 0x45, 0xF4, 0x00, 0x40, 0x99, 0x01 ])
if __name__ == '__main__':
    regress.main()
