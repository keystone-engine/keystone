#!/usr/bin/python
# Ingmar Steen, 2016

# This is to test RIP relative and absolute addressing

# Github issue: #32
# Author: Ingmar Steen

from keystone import *

import regress


class TestX86Nasm(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        # change the syntax to NASM
        ks.syntax = KS_OPT_SYNTAX_NASM

        # nasm uses abs for explicit absolute addressing
        encoding, count = ks.asm(b"lea eax, [__data]\n__data:")
        self.assertEqual(encoding, [ 0x8d, 0x05, 0x06, 0x00, 0x00, 0x00 ])

        # verify that explicit absolute addressing is indeed absolute
        encoding, count = ks.asm(b"nop\nnop\nlea eax, [__data]\n__data:")
        self.assertEqual(encoding, [ 0x90, 0x90, 0x8d, 0x05, 0x08, 0x00, 0x00, 0x00 ])


class TestX86Att(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        # change the syntax to AT&T
        ks.syntax = KS_OPT_SYNTAX_ATT

        # nasm uses abs for explicit absolute addressing
        encoding, count = ks.asm(b"lea __data, %eax\n__data:")
        self.assertEqual(encoding, [ 0x8d, 0x05, 0x06, 0x00, 0x00, 0x00 ])

        # verify that explicit absolute addressing is indeed absolute
        encoding, count = ks.asm(b"nop\nnop\nlea __data, %eax\n__data:")
        self.assertEqual(encoding, [ 0x90, 0x90, 0x8d, 0x05, 0x08, 0x00, 0x00, 0x00 ])


class TestX64Intel(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        # change the syntax to intel
        ks.syntax = KS_OPT_SYNTAX_INTEL

        # nasm uses abs for explicit absolute addressing
        encoding, count = ks.asm(b"lea eax, [__data]\n__data:")
        self.assertEqual(encoding, [ 0x8d, 0x05, 0x06, 0x00, 0x00, 0x00 ])

        # verify that explicit absolute addressing is indeed absolute
        encoding, count = ks.asm(b"nop\nnop\nlea eax, [__data]\n__data:")
        self.assertEqual(encoding, [ 0x90, 0x90, 0x8d, 0x05, 0x08, 0x00, 0x00, 0x00 ])


if __name__ == '__main__':
    regress.main()
