#!/usr/bin/python

# Test 'jmp dword ptr [5]' with both X86 Intel & ATT syntax

# Github issue: #6
# Author: Nguyen Anh Quynh

from keystone import *

import regress

class TestX86(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_32)

        ks.syntax = KS_OPT_SYNTAX_ATT
        # Assemble to get back insn encoding & statement count
        encoding, count = ks.asm(b"jmpl *5")
        # Assert the result
        self.assertEqual(encoding, [ 0xff, 0x25, 0x05, 0x00, 0x00, 0x00 ])

        ks.syntax = KS_OPT_SYNTAX_INTEL
        # Assemble to get back insn encoding & statement count
        encoding, count = ks.asm(b"jmp dword ptr [5]")
        # Assert the result
        self.assertEqual(encoding, [ 0xff, 0x25, 0x05, 0x00, 0x00, 0x00 ])

if __name__ == '__main__':
    regress.main()
