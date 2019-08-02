import binascii

from keystone import Ks, KS_ARCH_ARM, KS_MODE_ARM

ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)

assembly_text = \
    """
    sub sp, sp, #8
    push {sp, lr}
    bl #0xc6ab8
    ldr lr, [sp, #4]
    add sp, sp, #8
    pop {r2, r3}
    bx lr
    """

for i in range(100):
    output = ks.asm(assembly_text, 0x902c4, as_bytes=True)
    # print("{}: {}: {}".format(i, assembly_text, output))
    output_2 = ks.asm("b #0", 0x4, as_bytes=True)
    # print("{}: {}: {}".format(i, "b #0",  output_2))
