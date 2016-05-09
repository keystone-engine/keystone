#!/usr/bin/python
# Ingmar Steen, 2016

# This is to test RIP relative and absolute addressing

# Github issue: #32
# Author: Ingmar Steen

from keystone import *

import regress


class TestX64NasmRel(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        # change the syntax to NASM
        ks.syntax = KS_OPT_SYNTAX_NASM

        # nasm uses rel for rip relative addressing
        encoding, count = ks.asm(b"lea rax, [rel __data]\n__data:")
        self.assertEqual(encoding, [ 0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00 ])

        # verify that rip relative addressing is indeed rip relative
        encoding, count = ks.asm(b"nop\nnop\nlea rax, [rel __data]\n__data:")
        self.assertEqual(encoding, [ 0x90, 0x90, 0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00 ])


class TestX64NasmAbs(regress.RegressTest):
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


class TestX64AttRel(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        # change the syntax to AT&T
        ks.syntax = KS_OPT_SYNTAX_ATT

        # at&t syntax uses symbol(%rip) for rip relative addressing
        encoding, count = ks.asm(b"lea __data(%rip), %rax\n__data:")
        self.assertEqual(encoding, [ 0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00 ])

        # verify that rip relative addressing is indeed rip relative
        encoding, count = ks.asm(b"nop\nnop\nlea __data(%rip), %rax\n__data:")
        self.assertEqual(encoding, [ 0x90, 0x90, 0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00 ])


class TestX64AttAbs(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        # change the syntax to AT&T
        ks.syntax = KS_OPT_SYNTAX_ATT

        # nasm uses abs for explicit absolute addressing
        encoding, count = ks.asm(b"lea __data, %rax\n__data:")
        self.assertEqual(encoding, [ 0x48, 0x8d, 0x04, 0x25, 0x08, 0x00, 0x00, 0x00 ])

        # verify that explicit absolute addressing is indeed absolute
        encoding, count = ks.asm(b"nop\nnop\nlea __data, %rax\n__data:")
        self.assertEqual(encoding, [ 0x90, 0x90, 0x48, 0x8d, 0x04, 0x25, 0x0a, 0x00, 0x00, 0x00 ])


class TestX64IntelRel(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        # change the syntax to intel
        ks.syntax = KS_OPT_SYNTAX_INTEL

        # nasm uses rel for rip relative addressing
        encoding, count = ks.asm(b"lea rax, [rip + __data]\n__data:")
        self.assertEqual(encoding, [ 0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00 ])

        # verify that rip relative addressing is indeed rip relative
        encoding, count = ks.asm(b"nop\nnop\nlea rax, [rip + __data]\n__data:")
        self.assertEqual(encoding, [ 0x90, 0x90, 0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00 ])


class TestX64IntelAbs(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        # change the syntax to intel
        ks.syntax = KS_OPT_SYNTAX_INTEL

        # nasm uses abs for explicit absolute addressing
        encoding, count = ks.asm(b"lea rax, [__data]\n__data:")
        self.assertEqual(encoding, [ 0x48, 0x8d, 0x04, 0x25, 0x08, 0x00, 0x00, 0x00 ])

        # verify that explicit absolute addressing is indeed absolute
        encoding, count = ks.asm(b"nop\nnop\nlea rax, [__data]\n__data:")
        self.assertEqual(encoding, [ 0x90, 0x90, 0x48, 0x8d, 0x04, 0x25, 0x0a, 0x00, 0x00, 0x00 ])


if __name__ == '__main__':
    regress.main()
