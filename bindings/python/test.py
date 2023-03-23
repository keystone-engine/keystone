from keystone import *

print(keystone.__version__)
# separate assembly instructions by ; or \n
CODE = b"addi a0, x0, 2000; addi a2, a0, 100"

try:
  # Initialize engine in X86-32bit mode
  ks = Ks(KS_ARCH_RISCV, KS_MODE_32)
  encoding, count = ks.asm(CODE)
  print("%s = %s (number of statements: %u)" %(CODE, encoding, count))
except KsError as e:
  print("ERROR: %s" %e)
