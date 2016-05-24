#!/usr/bin/python

# Test 'call 5' with both X86 Intel & ATT syntax

# Github issue: #56
# Author: Nguyen Anh Quynh

from keystone import *

import regress

class TestX86ATT(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        # Assemble to get back insn encoding & statement count
        encoding, count = ks.asm(b"call 5", 0x2000)
        # Assert the result
        self.assertEqual(encoding, [ 0xe8, 0x00, 0xe0, 0xff, 0xff ])


class TestX86Intel(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        # Assemble to get back insn encoding & statement count
        encoding, count = ks.asm(b"call 5", 0x2000)
        # Assert the result
        self.assertEqual(encoding, [ 0xe8, 0x00, 0xe0, 0xff, 0xff ])


if __name__ == '__main__':
    regress.main()
