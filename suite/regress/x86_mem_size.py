#!/usr/bin/python

# Github issue: #73
# Author: fvrmatteo
# Description: missing memory size indicator

from keystone import *

import regress

class TestX86(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        try:
            # Assemble to get back insn encoding & statement count
            encoding, count = ks.asm(b"add ptr ss:[eax + ebx], 0x777")
        except KsError as e:
            if e.errno == KS_ERR_ASM_INVALIDOPERAND:
                #print("Got error KS_ERR_ASM_INVALIDOPERAND as expected")
                pass
            else:
                self.assertFalse(1, "ERROR: %s" % e)


if __name__ == '__main__':
    regress.main()
