#!/usr/bin/python

# Fill in the information in the form below when you create a new regression

# Github issue: #293
# Author: Aaron Adams

from keystone import *

import regress

class TestX86(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        # Assemble to get back insn encoding & statement count
        try:
            # An exception should be raised from the jnz exit:; being bad
            encoding, count = ks.asm(b"jnz exit:; add eax, ebx; exit: ret")
        except Exception, e:
            return
        raise Exception

if __name__ == '__main__':
    regress.main()
