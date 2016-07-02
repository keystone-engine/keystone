#!/usr/bin/python

# Test if "ljmp 0x33:08" throws an error.

# Github issue: #214
# Author: Duncan (mrexodia)

from keystone import *

import regress

class TestX86Intel(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        # Assemble with zero addr
        try:
            # Keystone (LLVM) syntax
            encoding, count = ks.asm("ljmp 0x33:08", 0)
            self.assertEqual(encoding, [ 0xea, 0x08, 0x00, 0x30, 0x00 ])
            # NASM syntax
            ks.syntax = KS_OPT_SYNTAX_NASM
            encoding2, count = ks.asm("jmp 0x33:08", 0)
            self.assertEqual(encoding, encoding2)
        except KsError as e:
            pass

if __name__ == '__main__':
    regress.main()
