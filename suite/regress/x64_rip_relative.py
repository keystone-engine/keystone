#!/usr/bin/python

# Test RIP relative instruction

# Github issue: #9
# Author: Nguyen Anh Quynh

from keystone import *

import regress

class TestX86(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        # Assemble to get back insn encoding & statement count
        encoding, count = ks.asm(b"MOV QWORD PTR [RIP+0xF55AF], 0xFF")
        # Assert the result
        self.assertEqual(encoding, [ 0x48, 0xc7, 0x05, 0xaf, 0x55, 0x0f, 0x00, 0xff, 0x00, 0x00, 0x00 ])

        encoding, count = ks.asm(b"MOV QWORD PTR [RIP+0xF55AF], 0xFFFFFFFFFFFFFFFE")
        # Assert the result
        self.assertEqual(encoding, [ 0x48, 0xC7, 0x05, 0xAF, 0x55, 0x0F, 0x00, 0xFE, 0xFF, 0xFF, 0xFF ])


if __name__ == '__main__':
    regress.main()
