#!/usr/bin/python

# Test BL <symbol> instruction with KS_OPT_SYM_RESOLVER for ARM32

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
        ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
        ks.sym_resolver = sym_resolver

        encoding, _ = ks.asm(b"""
                    sub r0, r0, r0
                    sub r1, r1, r1
                    bl  symBackward
                    """)
        self.assertEqual(encoding[-4:], [ 0xfc, 0xff, 0xff, 0xeb ])

        encoding, _ = ks.asm(b"bl  symForward")
        self.assertEqual(encoding, [ 0x06, 0x00, 0x00, 0xeb ])

if __name__ == '__main__':
    regress.main()
