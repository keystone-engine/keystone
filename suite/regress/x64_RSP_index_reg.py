#!/usr/bin/python

# Test some issues report in #254

# Github issue: #254
# Author: j123123

from keystone import *

import regress

class TestX86(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_64)

        encoding, _ = ks.asm(b"mov [rax+rsp], rsi")
        self.assertEqual(encoding, [ 0x48, 0x89, 0x34, 0x04 ])

        encoding, _ = ks.asm(b"mov [rsp+rax], rsi")
        self.assertEqual(encoding, [ 0x48, 0x89, 0x34, 0x04 ])

if __name__ == '__main__':
    regress.main()
