#!/usr/bin/python

# Test 'jmp 0' with both X86 Intel & ATT syntax

# Github issue: #5
# Author: Nguyen Anh Quynh

from keystone import *

import regress

class TestX86ATT(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_32)

        ks.syntax = KS_OPT_SYNTAX_ATT
        # Assemble to get back insn encoding & statement count
        encoding, count = ks.asm(b"jmp 0")
        # Assert the result
        self.assertEqual(encoding, [ 0xeb, 0xfe ])


class TestX86Intel(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        # Assemble to get back insn encoding & statement count
        encoding, count = ks.asm(b"jmp 0")
        # Assert the result
        self.assertEqual(encoding, [ 0xeb, 0xfe ])


if __name__ == '__main__':
    regress.main()
