#!/usr/bin/python

# Test symbols redefined/missing

# Github issue: #61
# Author: Nguyen Anh Quynh

from keystone import *

import regress

class TestSymbols(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_32)

        try:
            encoding, count = ks.asm(b"_label:; nop; _label:")
        except KsError as e:
            if e.errno == KS_ERR_ASM_SYMBOL_REDEFINED:
                #print("Got error KS_ERR_ASM_SYMBOL_REDEFINED as expected")
                pass
            else:
                self.assertFalse(1, "ERROR: %s" % e)

        try:
            encoding, count = ks.asm(b"mov eax, eflags")
        except KsError as e:
            if e.errno == KS_ERR_ASM_SYMBOL_MISSING:
                #print("Got error KS_ERR_ASM_SYMBOL_MISSING as expected")
                pass
            else:
                self.assertFalse(1, "ERROR: %s" % e)


if __name__ == '__main__':
    regress.main()
