#!/usr/bin/python

# Test some special instructions unsupported by LLVM

# Github issue: #58
# Author: Nguyen Anh Quynh

from keystone import *

import regress

class TestX86(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        # Assemble to get back insn encoding & statement count
        encoding, count = ks.asm(b"salc; int1; fsetpm")
        # Assert the result
        self.assertEqual(encoding, [ 0xd6, 0xf1, 0xdb, 0xe4 ])

if __name__ == '__main__':
    regress.main()
