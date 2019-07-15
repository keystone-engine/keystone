from keystone import *
import regress

# Github issue: #423
# Author: Edward Larson

class TestBranchRelativeAddressing(regress.RegressTest):
    def kstest(self, arch, mode, code, expect, syntax = 0, address = 0):
        ks = Ks(arch, mode)
        if syntax != 0:
            ks.syntax = syntax
        encoding, count = ks.asm(code, address)
        self.assertEqual(expect, encoding)

    def runTest(self):
        # 0x1fffffc is largest positive branch offset in PPC, 0x2000000 is largest negative branch offset
        self.kstest(KS_ARCH_PPC, KS_MODE_PPC32 | KS_MODE_BIG_ENDIAN, b"b 0x1fffffc", [0x49, 0xff, 0xff, 0xfc], address=0x0)
        self.kstest(KS_ARCH_PPC, KS_MODE_PPC32 | KS_MODE_BIG_ENDIAN, b"b 0x2000000", [0x49, 0xff, 0xff, 0xfc], address=0x4)
        self.kstest(KS_ARCH_PPC, KS_MODE_PPC32 | KS_MODE_BIG_ENDIAN, b"b 0x0", [0x4a, 0x00, 0x00, 0x00], address=0x2000000)
        # beyond max positive range, branch will wrap around to negative
        self.kstest(KS_ARCH_PPC, KS_MODE_PPC32 | KS_MODE_BIG_ENDIAN, b"b 0x2000000", [0x4a, 0, 0, 0], address=0x0)
        # beyond max negative range, branch will wrap ardound to positive
        self.kstest(KS_ARCH_PPC, KS_MODE_PPC32 | KS_MODE_BIG_ENDIAN, b"b 0x0", [0x49, 0xff, 0xff, 0xfc], address=0x2000004)


class TestBranchAbsoluteAddressing(regress.RegressTest):
    def kstest(self, arch, mode, code, expect, syntax = 0, address = 0):
        ks = Ks(arch, mode)
        if syntax != 0:
            ks.syntax = syntax
        encoding, count = ks.asm(code, address)
        self.assertEqual(expect, encoding)

    def runTest(self):
        # 0x1fffffc is largest absolute offset in PPC
        self.kstest(KS_ARCH_PPC, KS_MODE_PPC32 | KS_MODE_BIG_ENDIAN, b"ba 0x1fffffc", [0x49, 0xff, 0xff, 0xfe], address=0x0)
        self.kstest(KS_ARCH_PPC, KS_MODE_PPC32 | KS_MODE_BIG_ENDIAN, b"ba 0x1fffffc", [0x49, 0xff, 0xff, 0xfe], address=0x4)
        # beyond max positive range, branch will wrap around to negative
        self.kstest(KS_ARCH_PPC, KS_MODE_PPC32 | KS_MODE_BIG_ENDIAN, b"ba 0x2000000", [0x4a, 0, 0, 2], address=0x0)


if __name__ == '__main__':
    regress.main()