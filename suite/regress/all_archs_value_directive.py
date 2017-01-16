#!/usr/bin/python

# Test for relative branch offsets validation after an instruction encoded which
# is specified using in byte encoded form using .word directive.

# Author: Jatin Kataria

from keystone import (Ks, KS_ARCH_ARM, KS_ARCH_PPC, KS_MODE_ARM,
                      KS_MODE_PPC32, KS_MODE_BIG_ENDIAN)
import regress


class TestARM(regress.RegressTest):
    asm = b"""
mov r0, #0x30
bl #3230052728
.word 0xe6000010
mov r0, #0x41
bl #3230052712
"""

    def runTest(self):
        ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
        encoding, count = ks.asm(self.asm, 0xc0000000)
        expected_encoding = [48, 0, 160, 227, 91, 172, 33, 235, 16,
                             0, 0, 230, 65, 0, 160, 227, 84, 172, 33, 235]
        self.assertEqual(encoding, expected_encoding)


class TestPPC(regress.RegressTest):
    asm = b"""
li 4, 1;
addi 4, 4, 1;
bl 0xc000;
.long 0x38800001;
addi 5, 5, 1;
bl 0xc008;
"""

    def runTest(self):
        ks = Ks(KS_ARCH_PPC, KS_MODE_PPC32 + KS_MODE_BIG_ENDIAN)
        encoding, count = ks.asm(self.asm, 0xc0000000)
        expected_encoding = [56, 128, 0, 1, 56, 132, 0, 1, 72, 0, 191, 249, 56,
                             128, 0, 1, 56, 165, 0, 1, 72, 0, 191, 249]
        self.assertEqual(encoding, expected_encoding)


if __name__ == '__main__':
    regress.main()
