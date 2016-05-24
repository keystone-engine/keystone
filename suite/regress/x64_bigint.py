#!/usr/bin/python

# This tests alias instructions of MOV RDI, <big-int-numbers>

# Github issue: #12
# Author: Nguyen Anh Quynh

from keystone import *

import regress

class TestX86(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        # Assemble to get back insn encoding & statement count
        encoding, count = ks.asm(b"mov rdi, 0x1122334455")
        # Assert the result
        self.assertEqual(encoding, [ 0x48, 0xBF, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x00, 0x00 ])

        encoding, count = ks.asm(b"movabs rdi, 0x1122334455")
        # Assert the result
        self.assertEqual(encoding, [ 0x48, 0xBF, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x00, 0x00 ])

        encoding, count = ks.asm(b"movq rdi, 0x1122334455")
        # Assert the result
        self.assertEqual(encoding, [ 0x48, 0xBF, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x00, 0x00 ])

if __name__ == '__main__':
    regress.main()
