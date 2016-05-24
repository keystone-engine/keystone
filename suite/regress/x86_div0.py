#!/usr/bin/python

# Handle modulo 0 or div 0 issue

# Github issue: #68
# Author: Nguyen Anh Quynh

from keystone import *

import regress

CODE1 = b"jne 4014%0"
CODE2 = b"jne 4014/0"

class TestX86(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_32)

        try:
            encoding, count = ks.asm(CODE1)
        except KsError as e:
            if e.errno == KS_ERR_ASM_INVALIDOPERAND:
                #print("Got error KS_ERR_ASM_INVALIDOPERAND as expected")
                pass
            else:
                self.assertFalse(1, "ERROR: %s" % e)

        try:
            encoding, count = ks.asm(CODE2)
        except KsError as e:
            if e.errno == KS_ERR_ASM_INVALIDOPERAND:
                #print("Got error KS_ERR_ASM_INVALIDOPERAND as expected")
                pass
            else:
                self.assertFalse(1, "ERROR: %s" % e)

if __name__ == '__main__':
    regress.main()
