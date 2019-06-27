#!/usr/bin/python

# Test branches to absolute addresses for all architectures

# Github issue: #108
# Author: Fotis Loukos

from keystone import *
import regress

class TestARM(regress.RegressTest):
    def runTest(self):
        ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
        encoding, count = ks.asm(b"b #0x1010", 0x1000)
        self.assertEqual(encoding, [ 0x02, 0x00, 0x00, 0xea])
        encoding, count = ks.asm(b"bl #0x1010", 0x1000)
        self.assertEqual(encoding, [ 0x02, 0x00, 0x00, 0xeb])

class TestARMThumb(regress.RegressTest):
    def runTest(self):
        ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
        encoding, count = ks.asm(b"b #0x1010", 0x1000)
        self.assertEqual(encoding, [ 0x06, 0xe0])
        encoding, count = ks.asm(b"b.w #0x1010", 0x1000)
        self.assertEqual(encoding, [ 0x00, 0xf0, 0x06, 0xb8])
        encoding, count = ks.asm(b"b #0x101010", 0x1000)
        self.assertEqual(encoding, [ 0x00, 0xf1, 0x06, 0xb8])
        encoding, count = ks.asm(b"bl #0x1010", 0x1000)
        self.assertEqual(encoding, [ 0x00, 0xf0, 0x06, 0xf8])

class TestARM64(regress.RegressTest):
    def runTest(self):
        ks = Ks(KS_ARCH_ARM64, 0)
        encoding, count = ks.asm(b"b #0x1010", 0x1000)
        self.assertEqual(encoding, [ 0x04, 0x00, 0x00, 0x14])
        encoding, count = ks.asm(b"bl #0x1010", 0x1000)
        self.assertEqual(encoding, [ 0x04, 0x00, 0x00, 0x94])

class TestSPARC(regress.RegressTest):
    def runTest(self):
        ks = Ks(KS_ARCH_SPARC, KS_MODE_BIG_ENDIAN + KS_MODE_SPARC32)
        encoding, count = ks.asm(b"b 0x1010", 0x1000)
        self.assertEqual(encoding, [ 0x10, 0x80, 0x00, 0x04])

class TestMIPS(regress.RegressTest):
    def runTest(self):
        ks = Ks(KS_ARCH_MIPS, KS_MODE_MIPS32)
        encoding, count = ks.asm(b"b 0x1010", 0x1000)
        self.assertEqual(encoding, [ 0x03, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00])

class TestPPC(regress.RegressTest):
    def runTest(self):
        ks = Ks(KS_ARCH_PPC, KS_MODE_PPC32 + KS_MODE_BIG_ENDIAN)
        encoding, count = ks.asm(b"b 0x1010", 0x1000)
        self.assertEqual(encoding, [ 0x48, 0x00, 0x00, 0x10])

class TestSystemZ(regress.RegressTest):
    def runTest(self):
        ks = Ks(KS_ARCH_SYSTEMZ, KS_MODE_BIG_ENDIAN)
        encoding, count = ks.asm(b"j 0x1010", 0x1000)
        self.assertEqual(encoding, [ 0xa7, 0xf4, 0x00, 0x08])

if __name__ == '__main__':
    regress.main()
