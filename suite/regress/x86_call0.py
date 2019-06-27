#!/usr/bin/python

# Not really an issue. It works as it is supposed to, I'd like to know if there's any possibility to add a ks_option to allow such
# output

# Github issue: #267
# Author: krystalgamer

from keystone import *

import regress

class TestX86(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        # Assemble to get back insn encoding & statement count
        encoding, count = ks.asm(b"call 0")
        # Assert the result
        self.assertEqual(encoding, [ 0xE8, 0x00, 0x00, 0x00, 0x00 ])

if __name__ == '__main__':
    regress.main()
