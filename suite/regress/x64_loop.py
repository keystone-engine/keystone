#!/usr/bin/python

# Test LOOP imm

# Github issue: #95
# Author: Nguyen Anh Quynh

from keystone import *

import regress

class TestX86(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_64)

        encoding, _ = ks.asm(b"loop 0x7ff6bf912aad", 0x7FF6BF912A84)
        #encoding, _ = ks.asm(b"loop 0xad", 0x84)
        self.assertEqual(encoding, [ 0xe2, 0x27 ])


if __name__ == '__main__':
    regress.main()
