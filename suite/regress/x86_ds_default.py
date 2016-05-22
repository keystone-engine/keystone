#!/usr/bin/python

# Test to confirm that DS prefix is not emitted for data access

# Github issue: #9
# Author: Nguyen Anh Quynh

from keystone import *

import regress

class TestX86(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        # Assemble to get back insn encoding & statement count
        encoding, count = ks.asm(b"JMP DWORD PTR DS:[100]")
        # Assert the result
        self.assertEqual(encoding, [ 0xFF, 0x25, 0x64, 0x00, 0x00, 0x00 ])

if __name__ == '__main__':
    regress.main()
