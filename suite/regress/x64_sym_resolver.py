#!/usr/bin/python

# Test some issues with KS_OPT_SYM_RESOLVER

# Github issue: #244
# Author: Duncan (mrexodia)
# Author: endofunky

from keystone import *

import regress


class TestX86(regress.RegressTest):
    def runTest(self):
        symbol_table = {
            b"ZwQueryInformationProcess": 0x7FF98A050840,
            b"_l1": 0x1000,
            b"_l2": 0x1002,
            b"_l3": 0xAABBCCDD,
        }

        def sym_resolver(symbol, value):
            # is this the missing symbol we want to handle?
            if symbol in symbol_table:
                # put value of this symbol in @value
                value[0] = symbol_table[symbol]
                # we handled this symbol, so return true
                return True

            # we did not handle this symbol, so return false
            return False

        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        ks.sym_resolver = sym_resolver

        encoding, _ = ks.asm(b"call 0x7FF98A050840", 0x7FF98A081A38)
        self.assertEqual(encoding, [0xE8, 0x03, 0xEE, 0xFC, 0xFF])

        encoding, _ = ks.asm(b"call ZwQueryInformationProcess", 0x7FF98A081A38)
        self.assertEqual(encoding, [0xE8, 0x03, 0xEE, 0xFC, 0xFF])

        encoding, _ = ks.asm(b"mov rax, 80", 0x1000)
        self.assertEqual(encoding, [0x48, 0xC7, 0xC0, 0x50, 0x00, 0x00, 0x00])

        encoding, _ = ks.asm(b"jmp _l1; nop", 0x1000)
        self.assertEqual(encoding, [0xEB, 0xFE, 0x90])

        encoding, _ = ks.asm(b"jmp _l2; nop", 0x1000)
        self.assertEqual(encoding, [0xEB, 0x00, 0x90])

        encoding, _ = ks.asm(b"jmp _l3; nop", 0x1000)
        self.assertEqual(encoding, [0xE9, 0xD8, 0xBC, 0xBB, 0xAA, 0x90])


if __name__ == "__main__":
    regress.main()
