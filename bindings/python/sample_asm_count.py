#!/usr/bin/env python

# By Nguyen Anh Quynh <aquynh@gmail.com>, 2016
# Sample code for Keystone assembler engine.

# This shows how to get out of KsError the number of
# assembly instructions successfully compiled when error occur

from keystone import *

CODE = b"INC ecx; yyy; DEC edx" # input assembly with an invalid instruction

try:
    # Initialize engine in X86-32bit mode
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    encoding, count = ks.asm(CODE)
    print("%s = %s" %(CODE, encoding))
except KsError as e:
    print("ERROR: %s" %e)
    # get count via e.get_asm_count()
    count = e.get_asm_count()
    if count is not None:
        # print out the number of instructions succesfully compiled
        print("asmcount = %u" %e.get_asm_count())
