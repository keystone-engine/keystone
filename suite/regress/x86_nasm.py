#!/usr/bin/python

# This is to test NASM syntax

# Github issue: #xxx
# Author: Nguyen Anh Quynh

from keystone import *

import regress

class TestX86(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        # change the syntax to NASM
        ks.syntax = KS_OPT_SYNTAX_NASM

        # compile an instruction in NASM syntax
        encoding, count = ks.asm(b"mov dword [eax], 0x42424242")
        # Assert the result
        self.assertEqual(encoding, [ 0xc7, 0x00, 0x42, 0x42, 0x42, 0x42 ])

        # instructions separated by \n, and use ; for full line commenter
        encoding, count = ks.asm(b"add eax, ebx;inc ecx this comment is ignored\ninc edx")
        # Assert the result
        self.assertEqual(encoding, [ 0x01, 0xd8, 0x42 ])

if __name__ == '__main__':
    regress.main()
