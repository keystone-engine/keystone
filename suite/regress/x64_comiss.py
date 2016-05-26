#!/usr/bin/python

# Test LOOP imm

# Github issue: #92
# Author: Nguyen Anh Quynh

from keystone import *

import regress

class TestX86(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_64)

        encoding, _ = ks.asm(b"comiss xmm0, dword ptr [rip + 0x1ca568a]", 0x07FF6BF90CACF)
        self.assertEqual(encoding, [ 0x0F, 0x2F, 0x05, 0x8A, 0x56, 0xCA, 0x01 ])


if __name__ == '__main__':
    regress.main()
