#!/usr/bin/python
# Ingmar Steen, 2016

# This is to test call <label> on X86.

# Github issue: #64
# Author: Ingmar Steen


from keystone import *
import regress


class TestX86Nasm(regress.RegressTest):
    def runTest(self):
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        ks.syntax = KS_OPT_SYNTAX_NASM
        encoding, count = ks.asm(b"call label\n label:")
        self.assertEqual(encoding, [ 0xe8, 0x00, 0x00, 0x00, 0x00 ])


class TestX86Intel(regress.RegressTest):
    def runTest(self):
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        ks.syntax = KS_OPT_SYNTAX_INTEL
        encoding, count = ks.asm(b"call label; label:")
        self.assertEqual(encoding, [ 0xe8, 0x00, 0x00, 0x00, 0x00 ])


class TestX86Att(regress.RegressTest):
    def runTest(self):
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        ks.syntax = KS_OPT_SYNTAX_ATT
        encoding, count = ks.asm(b"call label; label:")
        self.assertEqual(encoding, [ 0xe8, 0x00, 0x00, 0x00, 0x00 ])


if __name__ == '__main__':
    regress.main()
