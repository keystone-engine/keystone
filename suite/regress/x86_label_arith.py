#!/usr/bin/python

# This is to test label arithmetic on x86

# Github issue: #66
# Author: Ingmar Steen


from keystone import *
import regress


VALID_ENCODINGS_1 = [
    [0x2d, 0x0a, 0x00, 0x00, 0x00],
    [0x81, 0xe8, 0x0b, 0x00, 0x00, 0x00],
    [0x83, 0xe8, 0x0b],
]


VALID_ENCODINGS_2 = [
    [0x2d, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x81, 0xe8, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x83, 0xe8, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
]


class TestX86Nasm1(regress.RegressTest):
    def runTest(self):
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        ks.syntax = KS_OPT_SYNTAX_NASM
        encoding, count = ks.asm(b"sub eax, foo + 5\nfoo:")
        self.assertIn(encoding, VALID_ENCODINGS_1)


class TestX86Nasm2(regress.RegressTest):
    def runTest(self):
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        ks.syntax = KS_OPT_SYNTAX_NASM
        encoding, count = ks.asm(b"sub eax, bar - foo\nfoo: dq 0\nbar:")
        self.assertIn(encoding, VALID_ENCODINGS_2)


class TestX86Intel1(regress.RegressTest):
    def runTest(self):
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        ks.syntax = KS_OPT_SYNTAX_INTEL
        encoding, count = ks.asm(b"sub eax, foo + 5;foo:")
        self.assertIn(encoding, VALID_ENCODINGS_1)


class TestX86Intel2(regress.RegressTest):
    def runTest(self):
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        ks.syntax = KS_OPT_SYNTAX_INTEL
        encoding, count = ks.asm(b"sub eax, bar - foo;foo: .quad 0;bar:")
        self.assertIn(encoding, VALID_ENCODINGS_2)


class TestX86Att1(regress.RegressTest):
    def runTest(self):
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        ks.syntax = KS_OPT_SYNTAX_ATT
        encoding, count = ks.asm(b"sub $foo + 5, %eax;foo:")
        self.assertIn(encoding, VALID_ENCODINGS_1)


class TestX86Att2(regress.RegressTest):
    def runTest(self):
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        ks.syntax = KS_OPT_SYNTAX_ATT
        encoding, count = ks.asm(b"sub $bar - foo, %eax;foo:;.quad 0;bar:")
        self.assertIn(encoding, VALID_ENCODINGS_2)


if __name__ == '__main__':
    regress.main()
