#!/usr/bin/python

# Test some x64 issues report in #9

# Github issue: #9
# Author: Nguyen Anh Quynh

from keystone import *

import regress

class TestX86(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_64)

        encoding, _ = ks.asm(b"MOVSX R12D, BYTE PTR [R15+RBP*1]")
        self.assertEqual(encoding, [ 0x45, 0x0F, 0xBE, 0x24, 0x2F ])

        encoding, _ = ks.asm(b"LEA RDX, [RAX]")
        self.assertEqual(encoding, [ 0x48, 0x8D, 0x10 ])


if __name__ == '__main__':
    regress.main()
