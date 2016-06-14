#!/usr/bin/python

# Test some x32 issues report in #9

# Github issue: #9
# Author: Nguyen Anh Quynh

from keystone import *

import regress

class TestX86(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_32)

        encoding, _ = ks.asm(b"MOVZX ECX,WORD PTR SS:[EAX*2+EBP-0x68]")
        self.assertEqual(encoding, [ 0x0F, 0xB7, 0x4C, 0x45, 0x98 ])

        encoding, _ = ks.asm(b"AND DWORD PTR DS:[EAX+0x70],0xFFFFFFFD")
        self.assertEqual(encoding, [ 0x83, 0x60, 0x70, 0xFD ])

        encoding, _ = ks.asm(b"MOV DWORD PTR [EBP-0x218],0x2080000")
        self.assertEqual(encoding, [ 0xC7, 0x85, 0xE8, 0xFD, 0xFF, 0xFF, 0x00, 0x00, 0x08, 0x02 ])

        encoding, _ = ks.asm(b"MOV DWORD PTR [ESP-0x218],0x2080000")
        self.assertEqual(encoding, [ 0xC7, 0x84, 0x24, 0xE8, 0xFD, 0xFF, 0xFF, 0x00, 0x00, 0x08, 0x02 ])

        encoding, _ = ks.asm(b"JMP 0xAA022104", 0xAA022104)
        self.assertEqual(encoding, [ 0xeb, 0xfe ])


if __name__ == '__main__':
    regress.main()
