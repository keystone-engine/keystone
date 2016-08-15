#!/usr/bin/python
# Ryan Hileman, 2016

# This is to test three-operand relative addressing using symbol math.

# Github issue: #226
# Author: Ryan Hileman

from keystone import *

import regress


class TestX86Nasm(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        # change the syntax to NASM
        ks.syntax = KS_OPT_SYNTAX_NASM

        # [eax + b - a] should assemble to [eax + length], or [eax + 6] here
        encoding, count = ks.asm(b"a:\nlea eax, [eax + b - a]\nb:")
        self.assertEqual(encoding, [ 0x8d, 0x80, 6, 0, 0, 0 ])

if __name__ == '__main__':
    regress.main()
