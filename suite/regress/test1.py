#!/usr/bin/python

# Fill in the information in the form below when you create a new regression

# Github issue: #987654321
# Author: Nguyen Anh Quynh

from keystone import *

import regress

class TestX86(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        # Assemble to get back insn encoding & statement count
        encoding, count = ks.asm(b"add eax, ebx")
        # Assert the result
        self.assertEqual(encoding, [ 0x01, 0xd8 ])

if __name__ == '__main__':
    regress.main()
