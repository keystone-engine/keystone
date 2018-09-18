#!/usr/bin/python

# Test BL <symbol> instruction with KS_OPT_SYM_RESOLVER for THUMB

# Github issue: #355
# Author: jan2642

from keystone import *

import regress

class TestARM(regress.RegressTest):
    def runTest(self):
        def sym_resolver(symbol, value):
            if symbol == "symBackward":
                value[0] = 0x0
                return True

            if symbol == "symForward":
                value[0] = 0x20
                return True

            return False

        # Initialize Keystone engine
        ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
        ks.sym_resolver = sym_resolver

        encoding, _ = ks.asm(b"""
                    sub r0, r0, r0
                    sub r0, r0, r0
                    bl  symBackward
                    """)
        self.assertEqual(encoding[-4:], [ 0xff, 0xf7, 0xfa, 0xff ])

        encoding, _ = ks.asm(b"bl  symForward")
        self.assertEqual(encoding, [ 0x00, 0xf0, 0x0e, 0xf8 ])

if __name__ == '__main__':
    regress.main()
