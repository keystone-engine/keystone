#!/usr/bin/python

# Github issue: #201
# Author: fvrmatteo
# Description: missing instructions SHR/SHL/SAR/SAL

from keystone import *

import regress

class TestX86(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        # Assemble to get back insn encoding & statement count
        encoding1, _ = ks.asm(b"shr eax, 1")
        encoding2, _ = ks.asm(b"shl dword ptr ss:[esp], 2")
        encoding3, _ = ks.asm(b"sar dword ptr ss:[0x10000000], 3")
        self.assertEqual(encoding1, [ 0xd1, 0xe8 ])
        self.assertEqual(encoding2, [ 0xc1, 0x24, 0x24, 0x02 ])
        self.assertEqual(encoding3, [ 0x36, 0xc1, 0x3d, 0x00, 0x00, 0x00, 0x10, 0x03 ])

if __name__ == '__main__':
    regress.main()