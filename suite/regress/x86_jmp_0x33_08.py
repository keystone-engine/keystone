#!/usr/bin/python

# Test if "jmp 0x33, 08" throws an error.

# Github issue: #214
# Author: Duncan (mrexodia)

from keystone import *

import regress

class TestX86Intel(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        # Assemble with zero addr
        try:
            encoding, count = ks.asm("jmp 0x33, 08", 0)
            self.fail()
        except KsError as e:
            pass

if __name__ == '__main__':
    regress.main() 