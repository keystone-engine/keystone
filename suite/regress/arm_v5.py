#!/usr/bin/python

# Test ARMv5 mode assembles only supported features.

# Author: Andrew O'Brien

from keystone import (Ks, KsError, KS_ARCH_ARM, KS_MODE_ARM, KS_MODE_V5)
import regress

class TestARM(regress.RegressTest):
    asm = b"""
    MOVT r0, #0
    """

    def runTest(self):
        # ARMv7 has the 'MOVT' instruction.
        ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
        encoding, count = ks.asm(self.asm)
        expected_v7_encoding = [0x00, 0x00, 0x40, 0xE3]
        self.assertEqual(encoding, expected_encoding)

        # ARMv5 does not.
        ks = Ks(KS_ARCH_ARM, KS_MODE_ARM+KS_MODE_V5)
        with self.assertRaises(KsError):
            encoding, count = ks.asm(self.asm)

