#!/usr/bin/python
# Nguyen Anh Quynh, 2016

# Fill in the information in the form below when you create a new regression

# Github issue: #12
# Author: Nguyen Anh Quynh

from keystone import *

import regress

class TestX86(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        # Assemble to get back insn encoding & statement count
        encoding, count = ks.asm("mov rdi, 0x1122334455")
        # Assert the result
        self.assertEqual(encoding, [ 0x48, 0xBF, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x00, 0x00 ])

if __name__ == '__main__':
    regress.main()
