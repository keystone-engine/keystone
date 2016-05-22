#!/usr/bin/python

# Test for oversize immediate

# Github issue: #9
# Author: Nguyen Anh Quynh

from keystone import *

import regress

CODE1 = b"MOV EAX, DWORD PTR [0xFFFFFFFFF]"
CODE2 = b"MOV EAX, DWORD PTR [0xFFFFFFFF]"

class TestX86(regress.RegressTest):
    def runTest(self):
        # Initialize Keystone engine
        ks = Ks(KS_ARCH_X86, KS_MODE_32)

        try:
            encoding, count = ks.asm(CODE2)
        except KsError as e:
            if e.errno == KS_ERR_ASM_INVALIDOPERAND:
                #print("Got error KS_ERR_ASM_INVALIDOPERAND as expected")
                pass
            else:
                self.assertFalse(1, "ERROR: %s" % e)

        encoding, count = ks.asm(CODE2)
        self.assertEqual(encoding, [ 0xA1, 0xFF, 0xFF, 0xFF, 0xFF ])

if __name__ == '__main__':
    regress.main()
