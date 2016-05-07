#!/usr/bin/python
# Nguyen Anh Quynh, 2016

# This is to test NASM syntax RIP relative and absolute addressing

# Github issue: #32
# Author: Ingmar Steen

from keystone import *

import regress

class TestX86_64(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        # change the syntax to NASM
        ks.syntax = KS_OPT_SYNTAX_NASM

        # nasm uses rel for rip relative addressing
        encoding, count = ks.asm("lea rax, [rel __data]\n__data:")
        self.assertEqual(encoding, [ 0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00 ])

        # verify that rip relative addressing is indeed rip relative
        encoding, count = ks.asm("nop\nnop\nlea rax, [rel __data]\n__data:")
        self.assertEqual(encoding, [ 0x90, 0x90, 0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00 ])

        # nasm uses abs for explicit absolute addressing
        encoding, count = ks.asm("lea rax, [abs __data]\n__data:")
        self.assertEqual(encoding, [ 0x48, 0x8b, 0x04, 0x25, 0x08, 0x00, 0x00, 0x00 ])

        # verify that explicit absolute addressing is indeed absolute
        encoding, count = ks.asm("nop\nnop\nlea rax, [abs __data]\n__data:")
        self.assertEqual(encoding, [ 0x90, 0x90, 0x48, 0x8b, 0x04, 0x25, 0x0a, 0x00, 0x00, 0x00 ])

if __name__ == '__main__':
    regress.main()
