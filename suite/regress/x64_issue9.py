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

        encoding, _ = ks.asm(b"ADD QWORD PTR [0x7FF68481C8ED], 0x1", 0x7FF6845CB982)
        self.assertEqual(encoding, [ 0x48, 0x83, 0x05, 0x63, 0x0F, 0x25, 0x00, 0x01 ])

        encoding, _ = ks.asm(b"JMP [0x123456789]", 0x123456789)
        self.assertEqual(encoding, [ 0xFF, 0x25, 0xFA, 0xFF, 0xFF, 0xFF ])

        encoding, _ = ks.asm(b"MOVABS RAX, QWORD PTR DS:[0x1234567890]", 0x7FFCA9FF1977)
        self.assertEqual(encoding, [ 0x48, 0xA1, 0x90, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00 ])


if __name__ == '__main__':
    regress.main()
