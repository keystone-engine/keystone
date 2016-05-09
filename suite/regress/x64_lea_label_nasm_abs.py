#!/usr/bin/python
# Ingmar Steen, 2016

# This is to test nasm syntax' explicit abs addressing

# Github issue: #32
# Author: Ingmar Steen

from keystone import *

import regress


class TestX64NasmLabelAbs(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        # change the syntax to NASM
        ks.syntax = KS_OPT_SYNTAX_NASM

        # nasm uses abs for explicit absolute addressing
        encoding, count = ks.asm(b"lea rax, [abs __data]\n__data:")
        self.assertEqual(encoding, [ 0x48, 0x8d, 0x04, 0x25, 0x08, 0x00, 0x00, 0x00 ])

        # verify that explicit absolute addressing is indeed absolute
        encoding, count = ks.asm(b"nop\nnop\nlea rax, [abs __data]\n__data:")
        self.assertEqual(encoding, [ 0x90, 0x90, 0x48, 0x8d, 0x04, 0x25, 0x0a, 0x00, 0x00, 0x00 ])


if __name__ == '__main__':
    regress.main()
