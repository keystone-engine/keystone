#!/usr/bin/python

# This tests the relative BLX instruction for Thumb-mode

# Github issue:  #166
# Author: McLovi9

from keystone import *

import regress

class TestARM(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
        # Assemble to get back insn encoding & statement count
        encoding, count = ks.asm(b"BLX 0xF4000134",addr=0xF400048A)
        # Assert the result
        self.assertEqual(encoding, [ 0xFF, 0xF7, 0x54, 0xEE ])

if __name__ == '__main__':
    regress.main()
