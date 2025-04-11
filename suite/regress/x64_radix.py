#!/usr/bin/python

# Test radix configuration for X86

# Github issue: #481 #436 #538
# Author: endofunky

from keystone import *

import regress


class TestX86(regress.RegressTest):
    def runTest(self):
        # Default value without ks_option
        ks = Ks(KS_ARCH_X86, KS_MODE_64)

        encoding, _ = ks.asm(b"add eax, 0x15", 0x1000)
        self.assertEqual(encoding, [0x83, 0xC0, 0x15])

        encoding, _ = ks.asm(b"add eax, 15h", 0x1000)
        self.assertEqual(encoding, [0x83, 0xC0, 0x15])

        encoding, _ = ks.asm(b"add eax, 15", 0x1000)
        self.assertEqual(encoding, [0x83, 0xC0, 0x0F])

        # NASM + RADIX16
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        ks.syntax = KS_OPT_SYNTAX_NASM | KS_OPT_SYNTAX_RADIX16
        encoding, _ = ks.asm(b"add eax, 15", 0x1000)
        self.assertEqual(encoding, [0x83, 0xC0, 0x15])

        # AT&T + RADIX16
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        ks.syntax = KS_OPT_SYNTAX_ATT | KS_OPT_SYNTAX_RADIX16
        encoding, _ = ks.asm(b"add $15, %eax", 0x1000)
        self.assertEqual(encoding, [0x83, 0xC0, 0x15])

        # Default with symbol resolver set (#481)
        def sym_resolver(symbol, value):
            return False

        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        ks.sym_resolver = sym_resolver

        encoding, _ = ks.asm(b"add eax, 15", 0x1000)
        self.assertEqual(encoding, [0x83, 0xC0, 0x0F])

        # Switching from 16 to 10
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        ks.syntax = KS_OPT_SYNTAX_NASM | KS_OPT_SYNTAX_RADIX16

        encoding, _ = ks.asm(b"add eax, 15", 0x1000)
        self.assertEqual(encoding, [0x83, 0xC0, 0x15])

        ks.syntax = KS_OPT_SYNTAX_NASM

        encoding, _ = ks.asm(b"add eax, 15", 0x1000)
        self.assertEqual(encoding, [0x83, 0xC0, 0x0F])


if __name__ == "__main__":
    regress.main()
