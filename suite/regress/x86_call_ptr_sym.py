#!/usr/bin/python
# Marco Bartoli, 2016

# This is to test call [label] on X86.

# Github issue: #271
# Author: Marco Bartoli (wsxarcher)


from keystone import *
import regress

def sym_resolver(symbol, value):
    if symbol == b'GetPhoneBuildString':
        value = 0x41b000
        return True
    return False

class TestX86Nasm(regress.RegressTest):
    def runTest(self):
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        ks.syntax = KS_OPT_SYNTAX_NASM

        dir(sym_resolver)

        ks.sym_resolver = sym_resolver
        encoding, count = ks.asm(b"call [GetPhoneBuildString]")
        self.assertEqual(encoding, [ 0xff, 0x15, 0x00, 0xb0, 0x41, 0x00 ])


class TestX86Intel(regress.RegressTest):
    def runTest(self):
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        ks.syntax = KS_OPT_SYNTAX_INTEL
        ks.sym_resolver = sym_resolver
        encoding, count = ks.asm(b"call [GetPhoneBuildString]")
        self.assertEqual(encoding, [ 0xff, 0x15, 0x00, 0xb0, 0x41, 0x00 ])


class TestX86Att(regress.RegressTest):
    def runTest(self):
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        ks.syntax = KS_OPT_SYNTAX_ATT
        ks.sym_resolver = sym_resolver
        encoding, count = ks.asm(b"call *GetPhoneBuildString")
        self.assertEqual(encoding, [ 0xff, 0x15, 0x00, 0xb0, 0x41, 0x00 ])


if __name__ == '__main__':
    regress.main()
