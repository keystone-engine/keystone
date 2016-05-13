#!/usr/bin/python
# Ingmar Steen, 2016

# This is to test nasm's default rel/abs directives.

# Github issue: #32
# Author: Ingmar Steen

from keystone import *

import regress


class TestX64(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        ks.syntax = KS_OPT_SYNTAX_NASM

        # default rel and no segment should yield PC relative
        encoding, count = ks.asm(b"default rel\nlea rax, [__data]\n__data:")
        self.assertEqual(encoding, [ 0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00 ])


class TestX64Abs(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        ks.syntax = KS_OPT_SYNTAX_NASM

        # default abs should yield absolute
        encoding, count = ks.asm(b"default rel\ndefault abs\nlea rax, [__data]\n__data:")
        self.assertEqual(encoding, [ 0x48, 0x8d, 0x04, 0x25, 0x08, 0x00, 0x00, 0x00 ])


class TestX64DS(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        ks.syntax = KS_OPT_SYNTAX_NASM

        # default rel and DS segment should yield PC relative
        encoding, count = ks.asm(b"default rel\nlea rax, ds:[__data]\n__data:")
        self.assertEqual(encoding, [ 0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00 ])


class TestX64CS(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        ks.syntax = KS_OPT_SYNTAX_NASM

        # default rel and CS segment should yield PC relative
        encoding, count = ks.asm(b"default rel\nlea rax, cs:[__data]\n__data:")
        self.assertEqual(encoding, [ 0x2e, 0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00 ])


class TestX64FS(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        ks.syntax = KS_OPT_SYNTAX_NASM

        # default rel and explicit non-CS/DS segment should yield absolute
        encoding, count = ks.asm(b"default rel\nlea rax, fs:[__data]\n__data:")
        self.assertEqual(encoding, [ 0x64, 0x48, 0x8d, 0x04, 0x25, 0x09, 0x00, 0x00, 0x00 ])


if __name__ == '__main__':
    regress.main()
