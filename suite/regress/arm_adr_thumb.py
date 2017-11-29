#!/usr/bin/python

from keystone import *
import regress

class TestARM(regress.RegressTest):
    def runTest(self):
        ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
        encoding, count = ks.asm(b"adr r0, #0x24440", 0x24428)
        self.assertEqual(encoding, [0x0f, 0xf2, 0x14, 0x00])
        encoding, count = ks.asm(b"adr r0, #0x24498", 0x2440a)
        self.assertEqual(encoding, [0x0f, 0xf2, 0x8c, 0x00])

if __name__ == '__main__':
    regress.main()
