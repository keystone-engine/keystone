#!/usr/bin/python
# Ingmar Steen, 2016

# This is to test whether labels are offset by the addr provided to ks.asm.

# Github issue: #32
# Author: Ingmar Steen

from keystone import *

import regress


class TestX86LeaLabel(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_32)

        encoding, count = ks.asm(b"lea eax, [__data]\n__data:", 0x480000)
        self.assertEqual(encoding, [ 0x8d, 0x05, 0x06, 0x00, 0x48, 0x00 ])


if __name__ == '__main__':
    regress.main()
