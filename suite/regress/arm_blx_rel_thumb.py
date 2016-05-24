#!/usr/bin/python

# This tests the relative BLX instruction for Thumb-mode

# Github issue: #36
# Author: Edgar Barbosa

from keystone import *

import regress

class TestARM(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
        # Assemble to get back insn encoding & statement count
        encoding, count = ks.asm(b"blx 0x86535200",addr=0x865351d4)
        # Assert the result
        self.assertEqual(encoding, [ 0x0, 0xf0, 0x14, 0xe8 ])

if __name__ == '__main__':
    regress.main()
